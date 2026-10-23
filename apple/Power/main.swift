// SPDX-License-Identifier: GPL-3.0-or-later

// mooring-power (design §5.1, §10.3): the daemon's child in the app's
// bundle. It runs `PowerHelper` over IOKit on the main run loop: power
// assertions (`IOPMAssertionCreateWithName`), the system's sleep and wake
// (`IORegisterForSystemPower`, `IOAllowPowerChange`) and the power source
// (`IOPSNotificationCreateRunLoopSource`). Its stdin carries the daemon's
// commands and is its lifetime: at its end it releases everything and
// exits. Its stdout carries the events; its stderr is the daemon's log.

import Foundation
import IOKit.ps
import IOKit.pwr_mgt
import MooringPower

// IOKit's message types, which Swift does not import from their macros
// (`iokit_common_msg(0x270)` and so on, IOKit/IOMessage.h).
let messageCanSystemSleep: UInt32 = 0xE000_0270
let messageSystemWillSleep: UInt32 = 0xE000_0280
let messageSystemHasPoweredOn: UInt32 = 0xE000_0300

/// `kIOPSUPSPowerValue` (IOKit/ps/IOPSKeys.h), which Swift does not import.
let upsPowerValue = "UPS Power"

/// The assertions' names, as `pmset -g assertions` lists them.
let assertionName = "Mooring exit" as CFString

/// IOKit for `PowerHelper`.
@MainActor
final class IOKitPower: PowerSystem {
    var rootPort: io_connect_t = 0
    private var assertions: [IOPMAssertionID] = []

    func readPowerSource() throws(PowerSystemError) -> PowerSourceValue {
        guard let info = IOPSCopyPowerSourcesInfo()?.takeRetainedValue() else {
            throw PowerSystemError(call: "IOPSCopyPowerSourcesInfo", status: kIOReturnError)
        }
        guard let type = IOPSGetProvidingPowerSourceType(info)?.takeUnretainedValue() as String?
        else {
            throw PowerSystemError(call: "IOPSGetProvidingPowerSourceType", status: kIOReturnError)
        }
        switch type {
        case kIOPSACPowerValue: return .ac
        // A UPS counts as battery: the mains is off.
        case kIOPSBatteryPowerValue, upsPowerValue: return .battery
        default:
            throw PowerSystemError(call: "IOPSGetProvidingPowerSourceType (\(type))", status: kIOReturnError)
        }
    }

    func holdAssertions() throws(PowerSystemError) {
        for type in [kIOPMAssertNetworkClientActive, kIOPMAssertionTypePreventUserIdleSystemSleep] {
            var id: IOPMAssertionID = 0
            let status = IOPMAssertionCreateWithName(
                type as CFString, IOPMAssertionLevel(kIOPMAssertionLevelOn), assertionName, &id)
            guard status == kIOReturnSuccess else {
                releaseAssertions()
                throw PowerSystemError(call: "IOPMAssertionCreateWithName(\(type))", status: status)
            }
            assertions.append(id)
        }
    }

    func releaseAssertions() {
        for id in assertions {
            IOPMAssertionRelease(id)
        }
        assertions.removeAll()
    }

    func allowSleep(token: Int) {
        IOAllowPowerChange(rootPort, token)
    }
}

/// Writes one event line on stdout, unbuffered.
func write(_ event: HelperEvent) {
    FileHandle.standardOutput.write(Data(event.line.utf8))
}

/// Writes one diagnostic line on stderr, the daemon's log.
func report(_ text: String) {
    FileHandle.standardError.write(Data((text + "\n").utf8))
}

let system = MainActor.assumeIsolated { IOKitPower() }
let helper = MainActor.assumeIsolated {
    PowerHelper(system: system, emit: write, report: report)
}

/// IOKit's system power callback, on the main run loop.
let powerCallback: IOServiceInterestCallback = { _, _, messageType, argument in
    let token = Int(bitPattern: argument)
    MainActor.assumeIsolated {
        switch messageType {
        case messageCanSystemSleep:
            // Idle sleep is not vetoed: while the exit serves, the
            // assertions keep it from being asked.
            system.allowSleep(token: token)
        case messageSystemWillSleep:
            let id = helper.willSleep(token: token)
            DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(25)) {
                MainActor.assumeIsolated { helper.sleepTimedOut(id: id) }
            }
        case messageSystemHasPoweredOn:
            helper.didWake()
        default:
            break
        }
    }
}

var notifyPort: IONotificationPortRef?
var notifier: io_object_t = 0
let rootPort = IORegisterForSystemPower(nil, &notifyPort, powerCallback, &notifier)
guard rootPort != 0, let notifyPort else {
    report("mooring-power: IORegisterForSystemPower failed")
    exit(1)
}
MainActor.assumeIsolated { system.rootPort = rootPort }
CFRunLoopAddSource(
    CFRunLoopGetMain(), IONotificationPortGetRunLoopSource(notifyPort).takeUnretainedValue(),
    .defaultMode)

let sourceCallback: IOPowerSourceCallbackType = { _ in
    MainActor.assumeIsolated { helper.powerSourceChanged() }
}
guard let sourceLoop = IOPSNotificationCreateRunLoopSource(sourceCallback, nil)?.takeRetainedValue()
else {
    report("mooring-power: IOPSNotificationCreateRunLoopSource failed")
    exit(1)
}
CFRunLoopAddSource(CFRunLoopGetMain(), sourceLoop, .defaultMode)

let startFailure = MainActor.assumeIsolated { () -> PowerSystemError? in
    do throws(PowerSystemError) {
        try helper.start()
        return nil
    } catch {
        return error
    }
}
if let startFailure {
    report("mooring-power: \(startFailure.call) failed with \(startFailure.status)")
    exit(1)
}

/// Reads the daemon's commands, one per line, on a thread of its own: a
/// pipe read blocks. Each command, and the end of the input, is handled on
/// the main run loop. A line that is not a command ends the helper, as the
/// end of the input does, after releasing everything.
Thread {
    let input = FileHandle.standardInput
    var pending = Data()
    while true {
        let chunk = input.availableData
        if chunk.isEmpty {
            break
        }
        pending.append(chunk)
        while let newline = pending.firstIndex(of: 0x0A) {
            let line = pending[pending.startIndex...newline]
            pending = Data(pending[pending.index(after: newline)...])
            switch Result(catching: { () throws(HelperCommand.Refusal) in try HelperCommand.decode(line: line) }) {
            case .success(let command):
                DispatchQueue.main.async {
                    MainActor.assumeIsolated { helper.handle(command) }
                }
            case .failure(let refusal):
                DispatchQueue.main.async {
                    MainActor.assumeIsolated {
                        report("mooring-power: the daemon wrote a line that is not a command (\(refusal))")
                        helper.inputEnded()
                        exit(2)
                    }
                }
                return
            }
        }
        if pending.count > maxHelperLineBytes {
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    report("mooring-power: the daemon wrote a line longer than the protocol allows")
                    helper.inputEnded()
                    exit(2)
                }
            }
            return
        }
    }
    DispatchQueue.main.async {
        MainActor.assumeIsolated {
            helper.inputEnded()
            exit(0)
        }
    }
}.start()

CFRunLoopRun()
