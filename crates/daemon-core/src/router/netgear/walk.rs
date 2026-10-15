// SPDX-License-Identifier: GPL-3.0-or-later

//! The one place that looks at `model.json`'s keys: a streaming walk over
//! serde_json that follows the allowlist's paths, checks each allowlisted
//! leaf's shape, and hands every other value to its [`Sink`] unread. The
//! parser's sink skips those values (serde_json skips a string without
//! copying it); the redactor's writes a placeholder of the value's type.
//!
//! A value the walk refuses on an allowlisted path (a leaf whose shape it
//! fails, a carrier list that is not an array, an element of it that is not
//! an object) goes to [`Sink::refused`] with its fault and its JSON type
//! only: the parser's sink stops the walk with the fault, the redactor's
//! withholds the value.

use std::collections::BTreeSet;
use std::fmt;

use mooring_model::Secret;
use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::error::Category;

use super::allowlist::{LeafSet, LeafShape, NetgearLeaf, Segment};
use crate::error::{CarrierFaultKind, FieldFaultKind, RouterParseError};
use crate::router::digit_runs_within;

/// The most elements the carrier list may have.
pub(crate) const MAX_ARRAY_ELEMENTS: u16 = 16;

/// An allowlisted leaf's value, its shape checked.
#[derive(Debug)]
pub(crate) enum LeafValue {
    /// A [`LeafShape::Bool`].
    Bool(bool),
    /// A [`LeafShape::Int`].
    Int(i128),
    /// A [`LeafShape::Text`].
    Text(String),
    /// A [`LeafShape::Line`], without its line feed.
    Line(String),
    /// A [`LeafShape::Digits`].
    Digits(String),
    /// A [`LeafShape::Secret`].
    Secret(Secret<String>),
}

/// An element of the carrier list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Element {
    /// The empty object that ends the list.
    Terminator,
    /// A carrier, by its index in the list.
    Entry(u16),
}

/// A JSON scalar's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scalar {
    /// A string.
    String,
    /// A number, integer or not.
    Number,
    /// `true` or `false`.
    Bool,
    /// `null`.
    Null,
}

/// What a refused value was: its JSON type, and for a string only whether
/// it was empty, so nothing of the value itself is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Found {
    /// A scalar of this type (a string that is not empty).
    Scalar(Scalar),
    /// The empty string.
    EmptyString,
    /// An array (already skipped).
    Array,
    /// An object (already skipped).
    Object,
}

impl Found {
    /// What a string was.
    fn string(text: &str) -> Self {
        if text.is_empty() {
            Self::EmptyString
        } else {
            Self::Scalar(Scalar::String)
        }
    }
}

/// What the walk tells as it goes. The structural events (objects, keys,
/// the carrier list) are those of the allowlisted paths; every value off
/// those paths is given to the `outside` methods unread.
pub(crate) trait Sink {
    /// An allowlisted leaf of the walk's set, its shape checked, seen once.
    fn leaf(&mut self, leaf: NetgearLeaf, element: Option<u16>, value: LeafValue);

    /// A value the walk refused where an allowlisted path expected it
    /// (`fault` is a `Field` or `Carriers` error naming the path), already
    /// read and known only by `found`. `Err` stops the walk with it.
    fn refused(&mut self, fault: RouterParseError, found: Found) -> Result<(), RouterParseError>;

    /// An object on an allowlisted path begins.
    fn begin_object(&mut self);

    /// A key of an object on an allowlisted path, before its value.
    fn key(&mut self, key: &str) -> Result<(), RouterParseError>;

    /// An object on an allowlisted path ends.
    fn end_object(&mut self);

    /// The carrier list begins.
    fn begin_carriers(&mut self);

    /// An element of the carrier list begins (its object follows).
    fn carrier(&mut self, element: Element);

    /// The carrier list ends.
    fn end_carriers(&mut self);

    /// A value off the allowlisted paths, unread.
    fn outside<'de, D: Deserializer<'de>>(&mut self, value: D) -> Result<(), D::Error>;

    /// A scalar where an allowlisted path expected an object; already read
    /// by the walk, so only its type is given.
    fn outside_scalar(&mut self, scalar: Scalar);

    /// An array where an allowlisted path expected an object, unread.
    fn outside_seq<'de, A: SeqAccess<'de>>(&mut self, seq: A) -> Result<(), A::Error>;

    /// The fault the sink met inside an `outside` value, if any.
    fn take_fault(&mut self) -> Option<RouterParseError>;
}

/// Walks `body`, telling `sink` the leaves of `set` and every other value.
pub(crate) fn walk<S: Sink>(
    body: &[u8],
    set: LeafSet,
    sink: &mut S,
) -> Result<(), RouterParseError> {
    let mut state = Walk {
        sink,
        set,
        fault: None,
        seen: BTreeSet::new(),
        carriers_seen: false,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let outcome = RootSeed { walk: &mut state }
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end());
    if let Some(fault) = state.fault.take().or_else(|| state.sink.take_fault()) {
        return Err(fault);
    }
    outcome.map_err(|error| classify(&error))
}

/// A serde_json error the walk did not raise itself, by its category only:
/// its message can quote the input, so it is dropped.
fn classify(error: &serde_json::Error) -> RouterParseError {
    match error.classify() {
        Category::Eof => RouterParseError::Truncated,
        Category::Io | Category::Syntax | Category::Data => RouterParseError::Syntax,
    }
}

/// The walk's state, shared by every seed and visitor.
struct Walk<'s, S> {
    sink: &'s mut S,
    set: LeafSet,
    fault: Option<RouterParseError>,
    seen: BTreeSet<(NetgearLeaf, Option<u16>)>,
    carriers_seen: bool,
}

impl<S: Sink> Walk<'_, S> {
    /// Records `fault` and stops the walk.
    fn stop<E: de::Error>(&mut self, fault: RouterParseError) -> E {
        self.fault = Some(fault);
        E::custom("the router walk stopped")
    }

    /// Records the error of a sink event, if any, and stops the walk.
    fn check<E: de::Error>(&mut self, result: Result<(), RouterParseError>) -> Result<(), E> {
        result.map_err(|fault| self.stop(fault))
    }

    /// Where `key`, under the allowlisted path `prefix`, leads.
    fn step(&self, prefix: Prefix, key: &str) -> Step {
        let depth = prefix.depth;
        for &leaf in NetgearLeaf::ALL {
            if !self.set.contains(leaf) {
                continue;
            }
            let path = leaf.segments();
            if path.len() <= depth || !prefix.is_prefix_of(path) {
                continue;
            }
            let Segment::Key(name) = path[depth] else {
                continue;
            };
            if name != key {
                continue;
            }
            return match path.get(depth + 1) {
                None => Step::Leaf(leaf),
                Some(Segment::Each) => Step::Carriers(Prefix {
                    leaf,
                    depth: depth + 2,
                }),
                Some(Segment::Key(_)) => Step::Object(Prefix {
                    leaf,
                    depth: depth + 1,
                }),
            };
        }
        Step::Outside
    }
}

/// An allowlisted path: the first `depth` segments of `leaf`'s path.
#[derive(Debug, Clone, Copy)]
struct Prefix {
    leaf: NetgearLeaf,
    depth: usize,
}

impl Prefix {
    /// The document itself: the empty prefix, of every leaf's path.
    const ROOT: Self = Self {
        leaf: NetgearLeaf::SessionUserRole,
        depth: 0,
    };

    fn is_prefix_of(self, path: &[Segment]) -> bool {
        let own = self.leaf.segments();
        own.get(..self.depth) == path.get(..self.depth)
    }
}

/// Where a key leads.
enum Step {
    /// To an allowlisted leaf.
    Leaf(NetgearLeaf),
    /// To an object on an allowlisted path.
    Object(Prefix),
    /// To the carrier list; the prefix is its elements'.
    Carriers(Prefix),
    /// Off the allowlisted paths.
    Outside,
}

/// A key, borrowed from the body when it has no escapes.
pub(crate) enum Key<'de> {
    Borrowed(&'de str),
    Owned(String),
}

impl Key<'_> {
    /// The key.
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Borrowed(key) => key,
            Self::Owned(key) => key,
        }
    }
}

/// Reads an object key.
pub(crate) struct KeySeed;

impl<'de> DeserializeSeed<'de> for KeySeed {
    type Value = Key<'de>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_str(KeyVisitor)
    }
}

struct KeyVisitor;

impl<'de> Visitor<'de> for KeyVisitor {
    type Value = Key<'de>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object key")
    }

    fn visit_borrowed_str<E: de::Error>(self, key: &'de str) -> Result<Self::Value, E> {
        Ok(Key::Borrowed(key))
    }

    fn visit_str<E: de::Error>(self, key: &str) -> Result<Self::Value, E> {
        Ok(Key::Owned(key.to_owned()))
    }

    fn visit_string<E: de::Error>(self, key: String) -> Result<Self::Value, E> {
        Ok(Key::Owned(key))
    }
}

/// The document: an object at the root.
struct RootSeed<'w, 's, S> {
    walk: &'w mut Walk<'s, S>,
}

impl<'de, S: Sink> DeserializeSeed<'de> for RootSeed<'_, '_, S> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de, S: Sink> Visitor<'de> for RootSeed<'_, '_, S> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<(), A::Error> {
        object(self.walk, Prefix::ROOT, None, map)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Err(self.walk.stop(RouterParseError::NotAnObject))
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Err(self.walk.stop(RouterParseError::NotAnObject))
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Err(self.walk.stop(RouterParseError::NotAnObject))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Err(self.walk.stop(RouterParseError::NotAnObject))
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Err(self.walk.stop(RouterParseError::NotAnObject))
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Err(self.walk.stop(RouterParseError::NotAnObject))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, _: A) -> Result<(), A::Error> {
        Err(self.walk.stop(RouterParseError::NotAnObject))
    }
}

/// The entries of an object on an allowlisted path.
fn object<'de, S: Sink, A: MapAccess<'de>>(
    walk: &mut Walk<'_, S>,
    prefix: Prefix,
    element: Option<u16>,
    mut map: A,
) -> Result<(), A::Error> {
    walk.sink.begin_object();
    while let Some(key) = map.next_key_seed(KeySeed)? {
        entry(walk, prefix, element, key.as_str(), &mut map)?;
    }
    walk.sink.end_object();
    Ok(())
}

/// One entry of an object on an allowlisted path: its key, then its value
/// by where the key leads.
fn entry<'de, S: Sink, A: MapAccess<'de>>(
    walk: &mut Walk<'_, S>,
    prefix: Prefix,
    element: Option<u16>,
    key: &str,
    map: &mut A,
) -> Result<(), A::Error> {
    let keyed = walk.sink.key(key);
    walk.check(keyed)?;
    match walk.step(prefix, key) {
        Step::Leaf(leaf) => map.next_value_seed(LeafSeed {
            walk,
            leaf,
            element,
        }),
        Step::Object(prefix) => map.next_value_seed(InnerSeed {
            walk,
            prefix,
            element,
        }),
        Step::Carriers(prefix) => map.next_value_seed(CarriersSeed { walk, prefix }),
        Step::Outside => map.next_value_seed(OutsideSeed { walk }),
    }
}

/// A value off the allowlisted paths.
struct OutsideSeed<'w, 's, S> {
    walk: &'w mut Walk<'s, S>,
}

impl<'de, S: Sink> DeserializeSeed<'de> for OutsideSeed<'_, '_, S> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        self.walk.sink.outside(deserializer)
    }
}

/// An allowlisted leaf's value.
struct LeafSeed<'w, 's, S> {
    walk: &'w mut Walk<'s, S>,
    leaf: NetgearLeaf,
    element: Option<u16>,
}

impl<'de, S: Sink> DeserializeSeed<'de> for LeafSeed<'_, '_, S> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        let Self {
            walk,
            leaf,
            element,
        } = self;
        if !walk.seen.insert((leaf, element)) {
            return Err(walk.stop(RouterParseError::Field {
                leaf,
                element,
                fault: FieldFaultKind::Duplicate,
            }));
        }
        match deserializer.deserialize_any(ShapeVisitor {
            shape: leaf.shape(),
        })? {
            Ok(value) => {
                walk.sink.leaf(leaf, element, value);
                Ok(())
            }
            Err((fault, found)) => {
                let refused = walk.sink.refused(
                    RouterParseError::Field {
                        leaf,
                        element,
                        fault,
                    },
                    found,
                );
                walk.check(refused)
            }
        }
    }
}

/// Reads a value against a shape: the value, or the fault and what the
/// value was.
struct ShapeVisitor {
    shape: LeafShape,
}

impl ShapeVisitor {
    fn integer(&self, value: i128) -> Result<LeafValue, (FieldFaultKind, Found)> {
        match self.shape {
            LeafShape::Int => Ok(LeafValue::Int(value)),
            LeafShape::Bool
            | LeafShape::Text { .. }
            | LeafShape::Line { .. }
            | LeafShape::Digits { .. }
            | LeafShape::Secret { .. } => {
                Err((FieldFaultKind::WrongType, Found::Scalar(Scalar::Number)))
            }
        }
    }

    fn text(&self, text: &str) -> Result<LeafValue, (FieldFaultKind, Found)> {
        self.text_shape(text)
            .map_err(|fault| (fault, Found::string(text)))
    }

    fn text_shape(&self, text: &str) -> Result<LeafValue, FieldFaultKind> {
        match self.shape {
            LeafShape::Bool | LeafShape::Int => Err(FieldFaultKind::WrongType),
            LeafShape::Text {
                min,
                max,
                digit_run,
            } => text_of(text, min, max, digit_run).map(|()| LeafValue::Text(text.to_owned())),
            LeafShape::Line { max, digit_run } => {
                let body = text.strip_suffix('\n').ok_or(FieldFaultKind::InvalidText)?;
                text_of(body, 1, max, digit_run).map(|()| LeafValue::Line(body.to_owned()))
            }
            LeafShape::Digits { min, max } => {
                if (min..=max).contains(&text.len())
                    && text.bytes().all(|byte| byte.is_ascii_digit())
                {
                    Ok(LeafValue::Digits(text.to_owned()))
                } else {
                    Err(FieldFaultKind::InvalidText)
                }
            }
            LeafShape::Secret { max } => {
                text_of(text, 1, max, max).map(|()| LeafValue::Secret(Secret::new(text.to_owned())))
            }
        }
    }

    fn other(found: Found) -> Result<LeafValue, (FieldFaultKind, Found)> {
        Err((FieldFaultKind::WrongType, found))
    }
}

/// Whether `text` is `min..=max` bytes of printable ASCII with no run of
/// more than `digit_run` digits.
fn text_of(text: &str, min: usize, max: usize, digit_run: usize) -> Result<(), FieldFaultKind> {
    if (min..=max).contains(&text.len())
        && text.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        && digit_runs_within(text, digit_run)
    {
        Ok(())
    } else {
        Err(FieldFaultKind::InvalidText)
    }
}

impl<'de> Visitor<'de> for ShapeVisitor {
    type Value = Result<LeafValue, (FieldFaultKind, Found)>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an allowlisted value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(match self.shape {
            LeafShape::Bool => Ok(LeafValue::Bool(value)),
            LeafShape::Int
            | LeafShape::Text { .. }
            | LeafShape::Line { .. }
            | LeafShape::Digits { .. }
            | LeafShape::Secret { .. } => {
                Err((FieldFaultKind::WrongType, Found::Scalar(Scalar::Bool)))
            }
        })
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(self.integer(i128::from(value)))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(self.integer(i128::from(value)))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(Self::other(Found::Scalar(Scalar::Number)))
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<Self::Value, E> {
        Ok(self.text(text))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Self::other(Found::Scalar(Scalar::Null)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Self::other(Found::Array))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Self::other(Found::Object))
    }
}

/// A value where an allowlisted path continues: an object is walked, any
/// other value is off the allowlisted paths (and the leaves beneath are
/// missing).
struct InnerSeed<'w, 's, S> {
    walk: &'w mut Walk<'s, S>,
    prefix: Prefix,
    element: Option<u16>,
}

impl<'de, S: Sink> DeserializeSeed<'de> for InnerSeed<'_, '_, S> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de, S: Sink> Visitor<'de> for InnerSeed<'_, '_, S> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<(), A::Error> {
        object(self.walk, self.prefix, self.element, map)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<(), A::Error> {
        self.walk.sink.outside_seq(seq)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        self.walk.sink.outside_scalar(Scalar::Bool);
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        self.walk.sink.outside_scalar(Scalar::Number);
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        self.walk.sink.outside_scalar(Scalar::Number);
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        self.walk.sink.outside_scalar(Scalar::Number);
        Ok(())
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        self.walk.sink.outside_scalar(Scalar::String);
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        self.walk.sink.outside_scalar(Scalar::Null);
        Ok(())
    }
}

/// The carrier list.
struct CarriersSeed<'w, 's, S> {
    walk: &'w mut Walk<'s, S>,
    prefix: Prefix,
}

impl<'de, S: Sink> DeserializeSeed<'de> for CarriersSeed<'_, '_, S> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        if self.walk.carriers_seen {
            return Err(self.walk.stop(RouterParseError::Carriers {
                fault: CarrierFaultKind::Duplicate,
            }));
        }
        self.walk.carriers_seen = true;
        deserializer.deserialize_any(self)
    }
}

impl<S: Sink> CarriersSeed<'_, '_, S> {
    /// A carrier list that is not an array, already read.
    fn not_an_array<E: de::Error>(self, found: Found) -> Result<(), E> {
        let refused = self.walk.sink.refused(
            RouterParseError::Carriers {
                fault: CarrierFaultKind::NotAnArray,
            },
            found,
        );
        self.walk.check(refused)
    }
}

impl<'de, S: Sink> Visitor<'de> for CarriersSeed<'_, '_, S> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the carrier list")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let Self { walk, prefix } = self;
        walk.sink.begin_carriers();
        let mut index = 0_u16;
        while seq
            .next_element_seed(ElementSeed {
                walk: &mut *walk,
                prefix,
                index,
            })?
            .is_some()
        {
            index += 1;
        }
        walk.sink.end_carriers();
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        self.not_an_array(Found::Object)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        self.not_an_array(Found::Scalar(Scalar::Bool))
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        self.not_an_array(Found::Scalar(Scalar::Number))
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        self.not_an_array(Found::Scalar(Scalar::Number))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        self.not_an_array(Found::Scalar(Scalar::Number))
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<(), E> {
        self.not_an_array(Found::string(text))
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        self.not_an_array(Found::Scalar(Scalar::Null))
    }
}

/// One element of the carrier list: an object, empty for the terminator.
struct ElementSeed<'w, 's, S> {
    walk: &'w mut Walk<'s, S>,
    prefix: Prefix,
    index: u16,
}

impl<'de, S: Sink> DeserializeSeed<'de> for ElementSeed<'_, '_, S> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        if self.index >= MAX_ARRAY_ELEMENTS {
            return Err(self.walk.stop(RouterParseError::Carriers {
                fault: CarrierFaultKind::TooLong,
            }));
        }
        deserializer.deserialize_any(self)
    }
}

impl<S: Sink> ElementSeed<'_, '_, S> {
    /// An element that is not an object, already read.
    fn not_an_object<E: de::Error>(self, found: Found) -> Result<(), E> {
        let refused = self.walk.sink.refused(
            RouterParseError::Carriers {
                fault: CarrierFaultKind::ElementNotAnObject,
            },
            found,
        );
        self.walk.check(refused)
    }
}

impl<'de, S: Sink> Visitor<'de> for ElementSeed<'_, '_, S> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a carrier object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let Self {
            walk,
            prefix,
            index,
        } = self;
        let Some(first) = map.next_key_seed(KeySeed)? else {
            walk.sink.carrier(Element::Terminator);
            walk.sink.begin_object();
            walk.sink.end_object();
            return Ok(());
        };
        walk.sink.carrier(Element::Entry(index));
        walk.sink.begin_object();
        entry(walk, prefix, Some(index), first.as_str(), &mut map)?;
        while let Some(key) = map.next_key_seed(KeySeed)? {
            entry(walk, prefix, Some(index), key.as_str(), &mut map)?;
        }
        walk.sink.end_object();
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        self.not_an_object(Found::Array)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        self.not_an_object(Found::Scalar(Scalar::Bool))
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        self.not_an_object(Found::Scalar(Scalar::Number))
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        self.not_an_object(Found::Scalar(Scalar::Number))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        self.not_an_object(Found::Scalar(Scalar::Number))
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<(), E> {
        self.not_an_object(Found::string(text))
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        self.not_an_object(Found::Scalar(Scalar::Null))
    }
}
