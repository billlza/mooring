<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!--
  Operator notes (not part of the text the user reads):
  - This is revision 2. The revision must equal `AgreementVersion::CURRENT` in
    crates/model/src/user.rs, and `user export` refuses users who accepted
    another revision (decision F9, design §9.2).
  - The text from the title on is pinned by its SHA-256
    (crates/export/tests/export/agreement_text.rs). Any change to it is a new
    revision: bump the constant and record the new digest in the same commit,
    and every user accepts again before their next file. These notes may
    change without a new revision.
  - Send users the text from the title on, never these notes (delivery.md,
    step 3 of section 1).
  - Revision 2 is the operator's revision of 2026-11-06 (design §9.4, §9.5):
    configurations through the user portal, by subscription link or JSON
    download, in the format CFM 0.5.x imports; payment through Stripe; every
    user on the portal, with files only as the backup when the portal cannot
    be reached. Users are asked to confirm it only once payment is built, so
    this revision lands with the payment work: merged earlier, it would make
    `user export` refuse every user who accepted revision 1. Never run a
    build of the unmerged revision against the real state: its `user agree`
    records revision 2, which a build of main then refuses to lower.
  - It covers the user portal (docs/portal-contract.md), so it sets
    `PORTAL_AGREEMENT_SINCE` (crates/model/src/portal.rs) to revision 2;
    agreement_text.rs checks that the text names the portal (门户) exactly
    when that gate is open.
  - The portal's commits cited here are on its branch
    feature/cfm-subscription-links, which had not been published when these
    notes were written; if that branch is rewritten, cite them again.
  - Clause 1 states the operator's payment decisions of 2026-11-06 (the
    portal's docs/payments.md):
    - Stripe, from the portal; a prepaid month, an auto-renewing month and
      traffic packs, whose contents and prices the portal's configuration
      holds; Mooring pulls paid orders from the portal and grants them.
    - Bank cards only. Stripe's Alipay terms (stripe.com/legal/alipay) and
      WeChat Pay's rules prohibit VPN and proxy services, and Alipay's
      recurring payments are by invitation.
    - Quotas count per billing cycle, the line's (design §7), so a month
      buys service until its expiry with that cycle's quota, and renewing
      early moves the expiry, not the quota. Cancelling auto-renewal is
      possible at the portal (to be built with payment) and through the
      operator.
    - Compensation: an outage on the operator's side of 8 hours or more,
      blocking included, is made up in extra time or traffic, more than the
      outage, and refunded by the outage's time only if the user insists.
      When the service ends, the unused days are refunded. Refunds go back
      to the card; once the card can take none, time or traffic replaces
      them. Nothing else is refunded.
    - The text names no price and makes no legal claim. Whether UK consumer
      law, including the rules on subscription contracts, adds to it is the
      operator's to check.
  - Clauses 2 and 5 state the portal's link rules (its docs/security.md §9
    and docs/contract/cfm-profiles-v2.md at commit a4359ea): shown once,
    stored as a digest, regenerated or disabled by the user, disabled by a
    password change. A suspended user (for quota, expiry, the operator, or
    abuse review) and one who has not accepted the current revision keep
    their link, which returns nothing until they are served again; only
    revocation, a ban included, ends it for good (the operator's decision
    of 2026-11-06; the portal pauses links since 120ca8a). A quota
    suspension ends at the next billing cycle only once Mooring lifts it
    there (planned with M5's apply), and the link works again after the
    next bundle. CFM's wording
    (「导入链接」, 「更新」, 「编辑」, 「QRCode」, the link shown in the
    profile's details) is CFM 0.5.1's: its zh-Hans catalogue and app.js at
    release/0.5.1 (8fd6a634). Its subscription fetch resolves the portal's
    name with the system's DNS even while it goes through CFM's own proxy
    (commands/subscriptions/fetch.rs:470), which clause 4 discloses.
  - Clause 4 adds the portal's host: a UK VPS of its own, neither a node nor
    the Mac (the operator's decision of 2026-11-06). What it keeps is the
    portal's schema at 520c358 (accounts, sessions, bindings, snapshot
    records, CFM profiles, links), the ban list (b094973's migration 3)
    and, once payment is built, its orders.
    - The operator deletes a user's portal account, and with it everything
      there, when the user is revoked or leaves (delivery.md, section 10);
      orders go with the account.
    - No backup or host snapshot of the portal's database may outlive
      these rules. The portal's 634e16e meets the two preconditions a4359ea
      did not.
      - Every command that deletes or overwrites rows then erases them
        (VACUUM, then wal_checkpoint(TRUNCATE)). When the database stays
        busy past 5 s, the command says what it did, fails, and names
        `erase-deleted`.
      - Its log names no account.
      - Out of its reach (its docs/security.md §11): old backups, host
        snapshots, and what the file system and disk keep. Clause 4 says
        that the host's provider may see what the disk keeps.
    - The ban list keeps an Argon2id digest of the email (19 MiB, two
      passes, one lane, a fixed public salt) since the portal's 1797f4e. A
      sign-up computes the same digest to check the list, and keeps nothing
      of it. No key kept out of the database and its backups is built, so a
      copy of them can still test addresses. Clause 4 says how far:
      - Whoever holds the data can test any addresses they have quickly:
        about a million an hour on one eight-core computer (OpenSSL 4.1's
        Argon2id, which reproduces the portal's pinned digest, on an M1
        Max, 2026-11-06).
      - Trying every numeric QQ address (fewer than 10^10) takes 7 to 10
        core-years at 20 to 30 ms each: out of casual reach, but days on
        rented computers. The salt being shared, one sweep finds every
        entry at once, in any copy.
    - Anyone who knows the portal's address can also ask its sign-up form,
      which answers a banned address as it answers a taken one (the
      portal's docs/security.md §10). It tells whether an email has an
      account or was banned, at 10 tries an hour per client network (its
      §5). Clause 4 says so under 「无法避免」.
    - The portal's command output names account numbers and Mooring ids.
      The operator runs those commands by hand and keeps their output out
      of cron, systemd and mail (delivery.md, section 0).
    - The portal keeps client addresses only in memory; its reverse proxy
      keeps no access log, and TLS ends on that host.
    - The Mac's new record is the payments it pulls, under the 13-month
      rule, built with the payment pull.
    - Stripe and the user's card issuer are its new third parties. What
      Stripe keeps is its Checkout and Radar data: the payment page's
      fields, the card's brand, last four digits, expiry and country, and
      the payer's IP address, location and device. The operator deletes a
      revoked user's saved card at Stripe; the payments themselves stay.
      The operator's Stripe business name and statement descriptor say
      nothing about the service.
  - Clause 4's other promises are revision 1's: decision F7 (retention,
    decided 2026-10-15 by delegation) and the design's "bytes and times
    only" rule (F16, §15.5). The deletion rules it promises must be built
    before M8 (design §11.5, §15.7, §22 M4/M5). Its other third parties are
    the nodes' DNS (Cloudflare DoH, §8.2), the VPS provider and the UK
    carrier; its server-side records are the usage bins and monthly files
    (§11.5), `last_active` (§11.1) and the Mac report (§15.9).
  - Clause 3 states the node's deny rules (design §8.2), and the ban.
    - The ban is the operator's decision of 2026-11-06, in their words:
      «额度用尽当然只暂停直到下一个计费周期，你用我的网从事非法活动被我抓了，我当然要封禁涉事账号。并且使其永远不得重复注册».
      A ban refunds nothing (the operator's decision, the same day).
    - Mooring's revocation records no reason, so a ban is the operator's
      own act at the portal, `mooring-portal ban` (portal b094973), beside
      the revocation in Mooring.
    - The portal deletes the account as for any revocation. It keeps for
      good the Argon2id digest of the email (above), trimmed and in lower
      case, with the ban's time, and answers a registration with that
      email as it answers one with a taken email. `unban` drops it.
    - The ban stops nothing but that email; the operator's binding by
      account number is the real gate. A payment identity added later
      must join clause 4 before users confirm this revision.
  - Clause 5's shared line: the operator undertakes to keep the line's
    monthly cap from being reached. Their example was more SIMs, which
    design §18 leaves to a later decision. A pause from the cap is an
    outage on the operator's side under clause 1.
  - Clause 6's three months: a user whose service expired three months
    before is revoked, by the operator until Mooring does it, and then
    deleted as clause 4 says (delivery.md, section 10).
-->
# 《Mooring 使用约定》第 2 版

请完整读完下面的内容。同意的话，请在与运营者的 FaceTime 语音通话中说：

> 我已阅读并同意《Mooring 使用约定》第 2 版

运营者记下你确认的日期后，你才能在门户上取得配置。

门户是运营者的网站：你在上面注册账号、付款、查看自己的服务状态和用量，并取得 CFM 配置。它的网址由运营者在 FaceTime 通话中告诉你。本约定说的“账户”，是你使用本服务的资格；“门户账号”，是你登录门户用的邮箱和密码。

## 这一版的变化

与第 1 版相比：
- 本服务改为收费，从门户付款，只接受银行卡；服务因运营者一方的原因连续 8 小时或更长时间无法使用时，运营者会补偿你（第 1 条）。
- 配置改为在门户上取得：用订阅链接导入 CFM，或者下载配置文件。订阅链接和配置文件一样，都是只属于你的凭据（第 2、5 条）。
- 门户所在的服务器和 Stripe 是新的保存地点：第 4 条写明它们保存什么、保存多久、谁能看到。
- 服务到期 3 个月后仍未续费，你的账户会被作废（第 6 条）。
- 用本服务从事违法活动的，会被封禁，以后也不能再注册（第 3 条）。

## 1. 收费，不转售

本服务收费，只提供给运营者信任的少数朋友。你不得出售、出租或转让本服务，也不得用它为其他人提供服务。

**怎么付费：**
- 付款从门户开始，在支付公司 Stripe 的付款页上完成，只接受银行卡。不要用转账或其他方式付钱给运营者。
- 可以买两种服务：
  - 按月套餐：一个月的服务。服务期内，每个计费周期有一定的流量配额。可以每次预付一个月，也可以开通自动续费。预付的可以提前续费：续上的时间从原来的到期日接着算，但不增加本计费周期的流量。
  - 流量包：额外的流量，在规定的天数内有效。
- 每种套餐和流量包包含多少天、多少流量，以及价格和币种，以门户上公布的为准。付款前，Stripe 的付款页会显示这次要付的金额。
- 付款后，运营者的电脑会定时从门户取回付款记录，为你开通或续期，所以要等一段时间才生效。到期后，服务会暂停，续费后恢复。

**自动续费：**
- 开通时，Stripe 会保存你的银行卡，之后每期自动扣款，直到你取消。
- 你可以随时取消：在门户上自己取消，或者在 FaceTime 通话中请运营者取消。取消后不再扣款，已付的这一期照常用到期满。
- 扣款失败时不会续期：到期后服务暂停，付款后恢复。

**中断时的补偿和退款：**
- 因为运营者一方的原因，服务连续 8 小时或更长时间无法使用时，运营者会补偿你：把你的服务期延长，延长的时间比中断的时间长；或者给你增加流量。
  - 无法使用，是指所有节点都连不上，或者所有用户的服务都被暂停。
  - 运营者一方的原因包括：运营者的电脑、线路或服务器出故障；服务器被封锁，包括只在你所用的运营商或地区被封锁；所有用户共用的月度流量上限用尽（第 5 条）。
  - 发生这种情况时，请按第 5 条告诉运营者。
- 你坚持要退款时，运营者按中断的时间退款。
- 运营者停止提供本服务时，按你还没用到的天数退款。
- 退款都退回你付款用的银行卡。这张卡已经不能退款时，改为补偿时间或流量；本服务停止时，就无法补偿了。
- 其他情况既不补偿也不退款，例如：你自己不再使用；你的配额用完或服务到期；你因为违反本约定被暂停、作废或封禁；你自己的设备或网络出了问题。

## 2. 配置和链接只给你一人

- 订阅链接和配置文件里都有只属于你的凭据：拿到你的订阅链接的人，就能取得你的配置。不要把它们转发或复制给任何人。
- 门户只在生成订阅链接的那一页显示一次链接，之后门户自己也找不回来；忘了就重新生成一个。不要把链接存进备忘录、密码管理工具或任何别的地方。
- 订阅链接只用来粘贴到 CFM 的「导入链接」里，不要在浏览器里打开它。复制链接前，关掉 Mac 的「接力」（否则它会经通用剪贴板传到你的其他 Apple 设备），以及剪贴板管理工具和输入法的云剪贴板；粘贴后，复制一段别的文字覆盖剪贴板。
- 不要截图、拍照或生成二维码，也不要把链接或配置文件的内容粘贴到聊天、邮件或文档里。CFM 会把链接保存在这份配置里，「QRCode」、「编辑」和配置的详情都会显示它：不要在别人面前、屏幕共享或远程控制（例如腾讯会议、向日葵、ToDesk）时打开门户或这份配置。
- 只在你的 Mac 上访问门户，不要用手机或国内的浏览器（例如 QQ 浏览器、360 浏览器），也不要让浏览器记住门户密码。
- 从门户下载的配置文件，以及运营者用加密映像给你的文件，导入 CFM 后都要删除，连同映像和聊天里的副本，并清空废纸篓。凭据已保存在 CFM 的钥匙串凭据库中，不会因此丢失。开着「时间机器」时，它的备份里可能留着下载过的文件，以及 CFM 保存的链接。
- 门户账号只给你自己用，不要把门户密码告诉任何人。修改门户密码会停用你的订阅链接，之后要重新生成链接，再导入 CFM。
- 门户的网址、订阅链接、映像、配置文件、《使用指南》和本约定都不要经过微信、QQ（包括文件传输助手和 QQ 邮箱）、其他国内邮箱或网盘，或中国大陆 Apple ID 的 iMessage 和 iCloud（包括同步到 iCloud 的「桌面」和「文稿」文件夹），也不要转发到手机。
- 订阅链接可能泄露时，立即在门户上重新生成（旧链接马上失效）或停用它，并告诉运营者：拿到链接的人可能已经取走了你的配置，运营者会为你更换凭据。
- 设备丢失、文件或链接可能外泄，或者有人向你索要它们时，请尽快告诉运营者。如果它们可能已经到了别人手里，运营者会作废你的旧凭据，换上新的（见第 5 条）。
- 设备被他人拿走或检查时，请在安全的时候告诉运营者。运营者会作废你的账户，并更换服务器。

## 3. 合法使用，不用 P2P

- 不得用于违反英国法律或英国运营商使用条款的活动。
- 不得使用 BitTorrent 等 P2P 下载或分享，不得通过 25 端口直接投递邮件。服务器会拦截 25 端口，以及它能识别出的 P2P 流量。
- 服务器拒绝中国大陆的网站和 IP。访问国内网站时，请按《使用指南》打开 CFM 的“中国大陆直连”开关，国内网站就会直接连接，不经过本服务。
- 所有流量都从运营者在英国的个人手机线路出去，在运营商那里记在运营者名下。
- 运营者确认你用本服务从事违法活动时，会封禁你：作废你的账户，删除你的门户账号，你的订阅链接永久失效，你以后也不能再注册门户账号。已付的费用不退。

## 4. 运营者能看到什么、保存多久

**运营者的电脑上会记录：**
- 你的名字（只供运营者自己辨认）、你的别名（一个随机编号，用于文件名）、你使用的 CFM 版本，以及你的流量配额和到期日；
- 按你的用户编号（不含你的名字）统计的流量：上行和下行的字节数，按服务器、协议和时间段汇总；
- 你最近一次使用的时间；
- 你的账户状态变化（启用、暂停、作废），以及运营者为你做的操作（例如导出配置、更换凭据）及其时间；
- 从门户取回的你的付款记录：订单编号、买了什么、金额和币种、付款时间、为你开通了什么，以及开通的时间；
- 你接受本约定的版本号和日期。

你的名字和别名只保存在运营者的电脑上，不会发送到服务器或门户。

**服务器（你在 CFM 里连接的节点）上会保存：**
- 按用户编号统计的流量明细和每月合计，以及每个编号最近一次使用的时间；
- 运营者的电脑定时发来的一份状态报告，供运营者在手机上查看。报告里有每位未作废用户的编号、账户状态、本计费周期的流量和最近一次使用的时间。新报告会覆盖旧报告。

**门户上会保存：**

门户在运营者租用的另一台英国服务器上，不是你在 CFM 里连接的那台。门户上有：
- 你的门户账号：账号编号、登录邮箱、密码的摘要（用 Argon2id 算出，门户不保存密码本身），以及注册和最近一次修改密码的时间。登录邮箱不要用能对应你实名的邮箱，例如 QQ 邮箱；
- 你的登录会话：令牌的摘要、登录时间和到期时间；
- 你的订阅链接：令牌的摘要和生成时间。门户只保存摘要，从摘要算不出链接；
- 你的门户账号对应的用户编号，以及绑定的时间；
- 运营者导入的你的服务状态：账户状态（包括暂停的原因和时间）、本计费周期的流量、配额和到期时间；
- 你的 CFM 配置，包括你的凭据和服务器地址。门户要把它原样交给 CFM，所以它不加密保存；
- 你的订单记录：买了什么、金额、付款时间和付款状态（包括退款），以及 Stripe 的付款编号。

门户不保存你的名字、别名和 IP 地址，也不保存你的银行卡信息：卡号只在 Stripe 的付款页上填写。

**Stripe 上会保存：**
- 你在付款页上填写的信息（例如邮箱和持卡人姓名）；卡的品牌、后四位、有效期和发卡国家；每笔付款的金额和时间；以及付款时 Stripe 为防欺诈自动收集的 IP 地址、大致位置和设备信息。运营者能在 Stripe 的后台看到这些，看不到完整的卡号。
- 开通自动续费时，你的银行卡，用于以后的扣款。

**运营者的电脑、服务器和门户不会记录：**
- 你访问的网站、域名、IP 地址、DNS 查询或网址；不保存任何连接日志；
- 你的 IP 地址和设备信息；
- 你在门户上看了哪些页面，以及 CFM 什么时候更新了订阅；
- 运营者不检查你的流量内容。

**无法避免：**
- 你在国内使用的网络（宽带或手机运营商）能看到你的设备在什么时间连接了哪个服务器、传了多少数据，但看不到经过本服务传输的内容。
- 你在国内使用的网络还能看到你访问了门户的域名：CFM 导入或「更新」订阅时，会先用你所在网络的 DNS 查询门户的域名，打开了「系统代理」时也是这样；不经过 CFM 访问门户时也一样。
- 你连接时，服务器能看到你的 IP 地址，但不记录。门户也一样：你访问门户时，它能看到你的 IP 地址，只用来限制请求的次数，不记录。
- 服务器提供商能看到你的 IP 地址、连接时间和流量大小；如果它控制了服务器，也能看到你访问的目标地址和域名，以及没有经过 HTTPS 加密的内容。
- 门户所在服务器的提供商能看到连接门户的 IP 地址；如果它控制了这台服务器，也能看到门户上保存的全部内容，包括你的配置和凭据，以及磁盘上可能残留的、门户已经删除的记录。
- 门户被攻破或数据外泄时，所有用户的登录邮箱、订单、配置和凭据会一起外泄。这时运营者会为所有用户更换凭据，你需要在门户上重新生成订阅链接并导入 CFM，或者重新下载配置文件。
- 知道门户网址的人，可以在注册页输入一个邮箱，从门户的回答看出这个邮箱是否已有门户账号或被封禁过（这两种情况门户的回答相同）。门户限制了每个网络尝试的次数，但挡不住只核对几个邮箱的人。
- 服务器通过 Cloudflare 的加密 DNS 服务（1.1.1.1 和 1.0.0.1）查询你访问的域名。Cloudflare 能看到这些域名和查询时间，但看到的是英国移动网络的地址，不是你的地址。
- 英国移动运营商能看到目标 IP 地址，以及大多数加密连接开头的域名（SNI），看不到你的地址，也看不到 HTTPS 加密的内容。
- 你访问的网站看到的是英国移动网络的地址。
- 你的发卡行会记录每笔付款的金额、时间和收款方的名称，并记在你的实名账户里。

**保存多久：**
- 运营者的电脑上：五分钟粒度的流量记录保存 7 天，按小时汇总的保存 35 天，按日和按月的合计保存 13 个月。
- 你的累计总量、最近一次使用的时间、账户状态变化和这些操作记录、付款记录、你接受本约定的记录，以及你的名字和别名，在你的账户作废 13 个月后全部删除。
- 服务器上：流量明细保存 48 小时，每月合计在当月结束 7 天后删除，运营者的电脑会在此之前取回它们；你最近一次使用的时间在你的账户作废、服务器不再为你服务时删除。
- 门户上：运营者每次导入新的服务状态和配置，都会替换旧的；登录会话在你退出登录或修改密码时删除，否则 30 天后到期，之后被清除。你的账户作废时（包括你退出时），运营者会删除你的门户账号，门户上关于你的记录随之删除。你被封禁时也一样，但门户会一直保留你登录邮箱的摘要和封禁的时间，用来拒绝这个邮箱再注册。门户不保存邮箱本身，但拿到门户数据的人，可以很快核对一个或一批邮箱是否被封禁过：一台普通电脑一两个小时就能核对一百万个。像 QQ 号邮箱这样由数字组成的邮箱，要把所有号码逐个试一遍，需要大量计算，随手做不到；但如果有人租用足够多的电脑，几天内就能试完，而且试完这一遍，就能同时认出所有被封禁过的这类邮箱。
- Stripe 上：你的账户作废时，运营者会取消你的自动续费，并删除 Stripe 上保存的你的银行卡。付款记录本身由 Stripe 按它自己的规定保存，运营者不能删除。
- 你可以随时请运营者告诉你，运营者保存了哪些关于你的记录。退出时，你可以请运营者立即删除运营者电脑上的这些记录，不必等 13 个月；门户上的记录在运营者删除你的门户账号时删除；服务器上的记录按上面的期限自动删除。

## 5. 连不上或被封锁时

- 先在 CFM 里换用另一个节点：名称含 `-reality` 的和名称含 `-hy2` 的节点互为备用。
- 服务器每天北京时间凌晨 3 点到 6 点之间可能更新配置或重启，会中断几分钟。
- 所有用户共用运营者线路的月度流量上限，运营者会确保它不会用尽。万一用尽，服务会暂停到下一个计费周期，并按第 1 条补偿。
- 你的流量配额用尽时，你的服务会暂停到下一个计费周期，买了流量包后也会恢复。服务到期后会暂停到你续费为止（见第 6 条）。
- CFM 不会自动更新配置。服务器被封、换了新服务器，或者你的凭据换了以后，运营者会更新你在门户上的配置。这时：
  - 用订阅链接导入的，在 CFM 里对这份配置选「更新」；
  - 用下载的文件导入的，到门户重新下载，导入新文件后，在 CFM 里删除旧的那份配置。

  连不上的时候，也可以先试一次「更新」。具体步骤见《使用指南》。
- 门户打不开、又需要新配置时，运营者会按备用的方式给你一份新文件：一个加密磁盘映像，口令由运营者在 FaceTime 通话中念给你。导入新文件后，在 CFM 里删除旧的那份配置。
- 账户被暂停时，订阅链接暂时取不到配置；恢复后，同一条链接照常可用：
  - 配额用尽的，暂停到下一个计费周期；
  - 到期的，暂停到你续费；
  - 你还没确认本约定的新版本的，暂停到你确认；
  - 运营者收到关于你的投诉、正在核查的，暂停到核查结束。

  账户作废或被封禁时，链接永久失效。
- 仍然不行的话，通过 FaceTime 语音告诉运营者：
  - 从什么时候开始；
  - 你用的是什么网络：哪家运营商，手机网络还是宽带；
  - 是否所有节点都不通。

  在微信等聊天软件里只约通话时间，不要提本服务，也不要发截图、链接或配置文件。
- 运营者会尽力维持服务，但不保证随时可用；8 小时或更长的中断按第 1 条补偿。

## 6. 更新与退出

- 本约定更新后，你需要重新确认新版本，门户才会继续为你提供配置。在此之前，已经导入 CFM 的配置仍然可以用，但门户不会给你新的配置。
- 你可以随时退出：运营者会作废你的账户、取消你的自动续费，并删除你的门户账号。已付的费用不退；第 1 条规定的退款除外。
- 服务到期 3 个月后仍未续费，运营者会作废你的账户，并按第 4 条删除你的记录。
- 你违反本约定时，运营者可以暂停、作废或封禁你的账户（第 3 条），已付的费用不退。
- 运营者停止提供本服务时，按第 1 条退款。
