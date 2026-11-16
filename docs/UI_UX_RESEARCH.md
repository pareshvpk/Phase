# UI/UX Research: Consumer Scam-SMS Safety App

Research-only report for an offline Android scam-SMS checker for Indian users. Product surface:
Jetpack Compose + Material 3, English/Hindi/Tamil, `minSdk 26`, `targetSdk 35`.

The design goal is a calm, trustworthy safety tool: the user should understand the verdict in
seconds, know the next safe action, and never see model internals or a false-precision risk score.

Method: reviewed official Material 3, Android, W3C and consumer-safety product guidance; checked
current public pages on 16 Nov 2026; computed contrast with the WCAG 2.x sRGB relative-luminance
formula. No application code was changed.

---

## 1. Key principles

- **Lead with one verdict, not a dashboard.** A user opening the app after a suspicious SMS needs
  one answer before evidence or settings: Safe, Suspicious, or Dangerous. Put the verdict in the
  first viewport and make everything else secondary. Material 3 hierarchy and layout guidance:
  [m3.material.io/components/cards/overview](https://m3.material.io/components/cards/overview).

- **Use plain outcome language, not model language.** Prefer “Likely scam”, “Some scam signs”, and
  “No scam signs found” over “classifier confidence”, “phishing probability”, or “risk score”.
  Google’s Pixel Scam Detection uses the concrete label “Likely scam” and a short explanation:
  [support.google.com/pixelphone/answer/16704479](https://support.google.com/pixelphone/answer/16704479).
  Microsoft’s warning guidance also calls for specific, actionable wording rather than vague
  alarms: [learn.microsoft.com/windows/win32/uxguide/mess-warn](https://learn.microsoft.com/en-us/windows/win32/uxguide/mess-warn).

- **Give 1–3 reasons maximum, in the user’s language.** Each reason should answer “what did the
  app notice?” in one short sentence, e.g. “It asks for your OTP”, “The link is not a bank
  website”, or “It creates urgency.” Do not list every rule that fired. Warning research supports
  concise, specific explanations; Google PAIR recommends explaining *why* in high-stakes
  predictions: [pair.withgoogle.com/chapter/explainability-trust](https://pair.withgoogle.com/chapter/explainability-trust/).

- **One clear primary action; everything else is secondary.** For a dangerous message the primary
  action should be the safest step the app can actually perform, such as “Open Messages to delete”
  or “Get help now”. Do not offer five equal buttons. Progressive disclosure keeps advanced detail
  out of the first view: [nngroup.com/articles/progressive-disclosure](https://www.nngroup.com/articles/progressive-disclosure/).

- **Do not use false precision.** A raw “87% risk” looks scientific but is hard for non-technical
  users to calibrate and invites over-trust. Use three categories, a short reason, and an explicit
  “not a guarantee” message. PAIR’s trust-calibration guidance: “help users calibrate their trust”
  and avoid explaining only *what* without *why*:
  [pair.withgoogle.com/chapter/explainability-trust](https://pair.withgoogle.com/chapter/explainability-trust/).

- **Never signal risk with colour alone.** Pair every verdict colour with an icon and a text label.
  This is required by WCAG 1.4.1 and is essential for colour-blind users and for users who do not
  associate red/green with safety:
  [w3.org/WAI/WCAG22/Understanding/use-of-color](https://www.w3.org/WAI/WCAG22/Understanding/use-of-color.html).

- **Meet WCAG AA and Android touch targets.** Body text needs at least 4.5:1 contrast; large text
  and meaningful non-text UI need at least 3:1. Interactive targets should be at least 48×48dp,
  with visible labels and generous spacing. Android accessibility guidance:
  [developer.android.com/guide/topics/ui/accessibility/apps](https://developer.android.com/guide/topics/ui/accessibility/apps).
  WCAG contrast: [w3.org/WAI/WCAG22/Understanding/contrast-minimum](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html).
  WCAG target size: [w3.org/WAI/WCAG22/Understanding/target-size-minimum](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html).

- **Reassure without guaranteeing safety.** “No scam signs found” is honest; “100% safe” is not.
  Even Google warns that Scam Detection “may not catch every scam”. Pair a safe result with one
  short reminder: “Never share your OTP or PIN.” Do not imply that a safe verdict protects the user
  from every future message.

- **Use a standard Material 3 bottom navigation bar for 3–5 top-level destinations.** Use icons
  plus labels, keep the selected destination obvious, and preserve each tab’s state. For this app,
  four destinations are enough; five would crowd Hindi/Tamil labels and large-font layouts:
  [m3.material.io/components/navigation-bar/overview](https://m3.material.io/components/navigation-bar/overview).

- **Keep brand colour and safety semantics separate.** Use purple/magenta for brand, surfaces, and
  primary actions; use dedicated green/amber/red roles only for verdicts. Do not reuse the same red
  for “Dangerous” and for form validation errors. Material 3 colour roles are designed as paired
  roles, with `on-*` colours for accessible content:
  [m3.material.io/styles/color/roles](https://m3.material.io/styles/color/roles).

- **Prefer brand colour over dynamic colour for v1.** Dynamic colour is useful for personalisation,
  but it can make warning containers look different on every phone and complicates contrast
  verification. Keep the verified purple/magenta scheme as the default; if dynamic colour is added
  later, keep verdict colours fixed:
  [developer.android.com/develop/ui/compose/designsystems/material3](https://developer.android.com/develop/ui/compose/designsystems/material3).

- **Design for older and first-time smartphone users.** Use one column, short sentences, obvious
  labels, 16sp+ body text, 48–56dp buttons, and no hover-only or gesture-only actions. NN/g’s
  senior-usability guidance: [nngroup.com/articles/usability-for-senior-citizens](https://www.nngroup.com/articles/usability-for-senior-citizens/).

- **Localise the layout, not just the strings.** Hindi and Tamil need more vertical room and often
  more horizontal space than English. Test with the longest safety strings, 200% font scaling, and
  the actual Noto fonts; do not put critical text inside images. Android per-app language guidance:
  [developer.android.com/guide/topics/resources/app-languages](https://developer.android.com/guide/topics/resources/app-languages).

---

## 2. How consumer safety apps present results

| Product | What the user sees | What is hidden or deferred | Useful takeaway |
|---|---|---|---|
| **Truecaller** | Colour-coded caller screen: blue for identified, red for spam, green for verified business, purple for time-sensitive verified business. Spam stats can show report count, time of day, and trend. | Detection internals and model details. | Colour is memorable, but must be backed by labels and icons. A red screen is a strong warning; do not use it for mere suspicion. [Source](https://www.truecaller.com/blog/features/what-do-the-different-caller-id-screen-colors-in-truecaller-mean) |
| **Google Messages** | Suspected-spam warning with a short reason, plus a “Not spam” escape hatch. Suspected spam can be moved to “Spam & blocked”. | Spam-model details and scores. | A reason plus a correction path reduces frustration and supports model improvement. [Source](https://blog.google/products-and-platforms/products/messages/safer-conversations-messages-verified-sms-and-spam-protection/) |
| **Google Pixel Scam Detection** | Notification with red warning icon and “Likely scam”; tapping opens an explanation with “More details”, “Done” (mark as scam), and “Not a scam”. Marking “Not a scam” suppresses detection for that conversation for a while. | Model internals; no percentage score. | “Likely scam” is concrete and actionable. The temporary suppression is a good false-positive recovery pattern. [Source](https://support.google.com/pixelphone/answer/16704479) |
| **Norton Genie / Scam Protection** | AI assistant accepts text, links, or images and gives real-time feedback on suspicious offers; Safe SMS alerts on suspicious texts. | Proprietary AI details and confidence internals. | Conversational detail can help, but should be optional rather than the first screen for low-literacy users. [Source](https://us.norton.com/blog/online-scams/norton-genie) |
| **Bitdefender Scamio** | Chat-style analysis of text, email, social messages, links, or QR codes; returns a verdict, tips, and a rating prompt. | Detection rules, databases, and model details. | “Verdict + practical tips” is useful; the chat metaphor is approachable but adds steps for a simple SMS check. [Source](https://www.bitdefender.com/en-us/consumer/scamio) |
| **Kaspersky Who Calls** | Spam category/reputation label and a block option. | Reputation-source details. | A short category plus a direct block action is easy to understand. [Source](https://support.kaspersky.com/WhoCalls/iOS1.19/en-US/174141.htm) |
| **Samsung Message Guard** | Invisible sandbox protection; no verdict screen. | Everything. | Silent protection is appropriate when confidence is low or the app cannot offer a meaningful action. Do not manufacture a warning just to show activity. [Source](https://docs.samsungknox.com/admin/fundamentals/whitepaper/samsung-knox-mobile-security/application-security/samsung-message-guard/) |

### Design implications

1. **Use three states, not a spectrum.** Safe / Suspicious / Dangerous is enough for a consumer SMS
   check. A numeric score adds cognitive load and implies precision the model may not have.
2. **Explain the trigger, not the technology.** “This message asks for your OTP” is useful;
   “TF-IDF vector exceeded threshold” is not.
3. **Make false positives easy to correct.** “Not a scam” / “I think this is safe” should be
   visible, with a short undo period and no penalty.
4. **Do not interrupt for every message.** Dangerous messages can justify a heads-up alert;
   suspicious messages should be quieter; safe messages should not notify at all.
5. **Keep the AI explanation optional.** A one-shot “Explain in simple words” disclosure is better
   for this audience than a full chatbot, which can obscure the verdict and encourage over-trust.

---

## 3. Recommended app structure

Use a Material 3 `NavigationBar` with four destinations. Icons should be 24dp, labels always
visible, selected destination shown with a filled icon and a tonal indicator. Keep the bar at the
standard height and respect system navigation insets.

### Destination 1: Check (Home)

- Compact purple/magenta hero: shield-with-lock illustration, app name, one-line promise such as
  “Check a message before you tap, pay, or share.”
- Large multiline paste field: “Paste the message here”.
- Primary filled pill button: “Check message”.
- Secondary text action: “Share a message to this app” (explains the Android share sheet).
- Recent check card: last verdict, short reason, “View” action. Do not show a history graph.
- Small trust line: “Works offline. Your message stays on your phone.” Put detailed privacy text
  in Settings/About, not in the hero.
- Empty state: one example scam type and a “See how it works” link, not a wall of tips.

### Destination 2: Alerts

- List only Suspicious and Dangerous messages. Safe messages do not belong here.
- Each row: verdict icon + label, sender label (“Unknown number” or saved name), one-line reason,
  relative time, and unread dot.
- Do not show the full message body in the list; open a detail screen for the preview.
- Filter chips: All / Suspicious / Dangerous. Keep the default “All”.
- Empty state: “No alerts. We’ll let you know if a message looks risky.”
- Alert detail uses the same result layout as Check, with “Open Messages” and “Not a scam” actions.

### Destination 3: Learn

- Six to eight plain-language scam cards: KYC/bank, delivery, OTP, lottery/prize, job, loan,
  investment, impersonation.
- Each card: “What they ask for”, “What to do”, “Report it”. Keep each section to 2–3 short lines.
- Persistent help card: “In India, call 1930” and a link to
  [cybercrime.gov.in](https://cybercrime.gov.in/). Include “Report online” but do not make the
  helpline a red alarm button.
- “Check a message” CTA at the end of each card.

### Destination 4: Settings

- Language: English / हिन्दी / தமிழ், with the language names in their own scripts.
- Appearance: System / Light / Dark. Do not expose a colour picker in v1.
- Alerts: on/off, heads-up for dangerous only, show safe checks, lock-screen preview off by
  default.
- Privacy: “Messages are checked on this phone”, history controls, “Clear history”.
- About: version, licences, privacy policy, feedback. Keep technical build information out of the
  main settings list.
- Developer diagnostics: hidden behind a long-press or a debug build, never visible to normal users.

### Navigation behaviour

- Preserve scroll position and state per tab.
- Share-sheet entry opens Check with the message prefilled; notification entry opens the relevant
  alert detail.
- Back from a result returns to the previous tab, not always to Home.
- On screens at least 600dp wide, replace the bottom bar with a navigation rail; keep the same four
  destinations and labels.

---

## 4. Recommended result-screen layout

The order below is deliberate: verdict → why → action → optional detail. Nothing technical appears
above the optional disclosure.

### 4.1 Top to bottom

1. **Top app bar**
   - Back arrow, screen title (“Check result”), overflow menu with “Copy result”, “Share”, and
     “Report a problem”. Do not put a score or model name here.

2. **Verdict hero card**
   - A compact glossy shield-with-lock illustration, 88–112dp, decorative only.
   - Severity label: “Likely scam” / “Some scam signs” / “No scam signs found”.
   - One-sentence summary: “This message asks for your OTP and creates urgency.”
   - Tinted container in the verdict colour; icon + text, never colour alone.
   - Keep this card above the fold. On the result screen it should be more compact than the Home
     hero so the first reason and action are visible without scrolling.

3. **“What we noticed” section**
   - Heading: “What we noticed”.
   - Maximum three reason rows. Each row: 20–24dp icon, bold 3–6 word title, one short sentence.
   - Examples: “Asks for OTP — No real bank asks you to share an OTP in a message.”; “Urgent
     language — It pressures you to act within minutes.”; “Unusual link — The link does not match
     the bank’s website.”
   - If there are no reasons (safe), use one reassuring line and one caution: “We did not find
     common scam signs. Still never share your OTP or PIN.”

4. **Primary action**
   - One full-width filled pill button, 52–56dp high.
   - Dangerous: “Open Messages to delete” (or “Get help now” if the app cannot open the inbox).
   - Suspicious: “Check safely before you act”.
   - Safe: “Check another message”.
   - Do not label an action “Delete” if the app cannot actually delete the original SMS.

5. **Secondary actions**
   - Text buttons or a single overflow: “I think this is safe”, “Get help”, “Report a mistake”.
   - Keep these visually quieter than the primary action.
   - After “I think this is safe”, show a short confirmation and an Undo action.

6. **What to do next (progressive disclosure)**
   - Collapsed by default for Safe and Suspicious; expanded for Dangerous.
   - Two or three numbered steps maximum: “Do not reply or tap the link”, “Delete and block the
     sender”, “If you shared details, call 1930”.
   - Use plain verbs, not policy language.

7. **Optional AI explanation**
   - Text button: “Explain in simple words” with a chevron. Do not call it “AI analysis” on the
     main screen.
   - On expansion, show 2–4 short sentences: what was noticed, why it matters, what to do.
   - Label: “Generated on your phone. It can make mistakes.”
   - If the explanation conflicts with the verdict, say “This message has mixed signals. Be
     careful.” Do not let the explanation silently override the safety verdict.
   - If unavailable, hide the section or show “Explanation is not available right now.” Never show
     an error code.

8. **Message preview**
   - Collapsed: “Show message”.
   - When expanded, render the SMS as plain text, with links disabled or shown as non-clickable
     text. Keep the preview visually distinct from app-generated text.
   - Do not show sender metadata, SIM slot, encoding, timestamps, or raw URLs.

9. **Feedback footer**
   - “Was this helpful?” Yes / No.
   - “Report a mistake” opens a short reason list. This is the correction path for false positives
     and false negatives.
   - Do not show a thank-you interstitial; use a small inline confirmation.

### 4.2 State-specific copy

| State | Hero label | One-line summary | Primary action |
|---|---|---|---|
| Safe | “No scam signs found” | “We did not find common scam signs in this message.” | “Check another message” |
| Suspicious | “Some scam signs” | “This message has a few warning signs. Check before you act.” | “Check safely before you act” |
| Dangerous | “Likely scam” | “This message looks like a scam. Do not tap links or share details.” | “Open Messages to delete” |

Use “Dangerous” as the internal severity name, but lead with “Likely scam” on screen. It is more
concrete for a first-time smartphone user and matches the pattern used by Google Pixel Scam
Detection.

The three-level model is a traffic-light pattern: green, amber, red. It is fast to scan, but it
fails for colour-blind users and for users who read red as “error” rather than “scam”. Always pair
the colour with a distinct icon and a text label; never use red for mere suspicion.

### 4.3 Alert / notification UX

- **Dangerous:** heads-up notification with red warning icon, title “Likely scam message”, body
  “From [sender]. Tap to review.” Actions: “Review” and “Not a scam”.
- **Suspicious:** standard notification, no heads-up. Same actions.
- **Safe:** no notification. Optionally show a badge on Alerts only if the user has enabled
  “Show safe checks”.
- One notification per conversation per day unless the verdict escalates.
- Marking “Not a scam” suppresses alerts for that conversation for a while and offers Undo.
- Lock screen: show “1 suspicious message” without sender or message text by default. Detailed
  previews are opt-in.
- Ask for notification permission with a plain explanation, not on first launch before the user
  understands the value.

---

## 5. Colour palette (purple/magenta brand)

### 5.1 Colour strategy

- **Brand roles** use purple/magenta. **Verdict roles** use green/amber/red and are never remapped
  by dynamic colour.
- Use `surfaceContainer` tones for cards and sheets, not pure white cards on a white background.
  M3 recommends surface-container roles for contained areas:
  [m3.material.io/blog/tone-based-surface-color-m3](https://m3.material.io/blog/tone-based-surface-color-m3).
- Pair each base colour with its `on-*` colour. Do not place arbitrary text colours on branded
  containers.
- The palette below is a proposal, not the current app theme. All ratios were computed with the
  WCAG sRGB formula; 4.5:1 is the target for normal text, 3:1 for large text and meaningful
  non-text UI.

### 5.2 Light theme

| Role | Hex | Paired with | Contrast |
|---|---|---|---|
| Primary | `#8A1C62` | `onPrimary #FFFFFF` | **8.67:1** |
| Primary container | `#FFD8EC` | `onPrimaryContainer #3B0026` | **13.42:1** |
| Secondary | `#66516E` | `onSecondary #FFFFFF` | **7.08:1** |
| Secondary container | `#F0DCEC` | `onSecondaryContainer #241A2A` | **12.86:1** |
| Background | `#FFF7FB` | `onBackground #211A1E` | **16.20:1** |
| Surface | `#FFFBFE` | `onSurface #211A1E` | **16.64:1** |
| Surface container | `#F9E8F2` | `onSurface #211A1E` | **14.50:1** |
| On surface variant | `#52434B` | on `Surface #FFFBFE` | **9.05:1** |
| Outline | `#84707A` | on `Surface #FFFBFE` | **4.47:1** (non-text) |
| Outline variant | `#D6C1CC` | on `Surface #FFFBFE` | **1.66:1** (decorative only) |
| Error | `#B3261E` | `onError #FFFFFF` | **6.54:1** |
| Error container | `#FFDAD6` | `onErrorContainer #410002` | **13.26:1** |
| Safe | `#146C43` | on `Surface #FFFBFE` | **6.29:1** |
| Safe container | `#DCF5E4` | `onSafeContainer #073B1E` | **11.02:1** |
| Suspicious | `#8A5A00` | on `Surface #FFFBFE` | **5.78:1** |
| Suspicious container | `#FFF0C9` | `onSuspiciousContainer #3F2A00` | **12.03:1** |
| Dangerous | `#B3261E` | on `Surface #FFFBFE` | **6.38:1** |
| Dangerous container | `#FFDAD6` | `onDangerousContainer #410002` | **13.26:1** |

Supporting light surfaces: `surfaceContainerLowest #FFFFFF`, `surfaceContainerLow #FDF1F7`,
`surfaceContainer #F9E8F2`, `surfaceContainerHigh #F3DDEA`,
`surfaceContainerHighest #EDD2E2`. On-surface contrast for low/container/high/highest is
**15.52:1 / 14.50:1 / 13.27:1 / 12.12:1**.

### 5.3 Dark theme

| Role | Hex | Paired with | Contrast |
|---|---|---|---|
| Primary | `#FFAFD6` | `onPrimary #57103A` | **8.02:1** |
| Primary container | `#7C1C57` | `onPrimaryContainer #FFD8EC` | **7.54:1** |
| Secondary | `#D8C0DF` | `onSecondary #3B2A42` | **7.85:1** |
| Secondary container | `#523F5B` | `onSecondaryContainer #F0DCEC` | **7.27:1** |
| Background | `#191016` | `onBackground #F2DEE8` | **14.54:1** |
| Surface | `#191016` | `onSurface #F2DEE8` | **14.54:1** |
| Surface container | `#261A22` | `onSurface #F2DEE8` | **13.08:1** |
| On surface variant | `#D4BFC9` | on `Surface #191016` | **10.73:1** |
| Outline | `#9D8994` | on `Surface #191016` | **5.71:1** (non-text) |
| Outline variant | `#52434C` | on `Surface #191016` | **2.01:1** (decorative only) |
| Error | `#FFB4AB` | `onError #690005` | **7.72:1** |
| Error container | `#93000A` | `onErrorContainer #FFDAD6` | **7.24:1** |
| Safe | `#7BD79A` | on `Surface #191016` | **10.67:1** |
| Safe container | `#0B3D22` | `onSafeContainer #B9F2CB` | **9.75:1** |
| Suspicious | `#FFC24D` | on `Surface #191016` | **11.60:1** |
| Suspicious container | `#4A3400` | `onSuspiciousContainer #FFE08A` | **9.13:1** |
| Dangerous | `#FFB4AB` | on `Surface #191016` | **10.97:1** |
| Dangerous container | `#5E1216` | `onDangerousContainer #FFDAD6` | **10.32:1** |

Supporting dark surfaces: `surfaceContainerLowest #130B10`, `surfaceContainerLow #21161D`,
`surfaceContainer #261A22`, `surfaceContainerHigh #31222C`,
`surfaceContainerHighest #3D2B36`. On-surface contrast for low/container/high/highest is
**13.69:1 / 13.08:1 / 11.74:1 / 10.26:1**.

### 5.4 Usage rules

- Use **container + on-container** for large verdict panels; ratios above 9:1 leave room for
  gradients, disabled states, and font rendering differences.
- Use solid Safe/Suspicious/Dangerous for icons, small accent bars, and large text. They pass
  4.5:1 on the paired surface in both themes.
- `outlineVariant` is decorative only. Do not use it as the only boundary of an input or button;
  at 1.66:1 light / 2.01:1 dark it does not meet non-text contrast.
- Keep `error` for form errors. Define separate `safe`, `suspicious`, and `dangerous` custom roles
  for verdicts so an input error cannot accidentally turn into a scam warning.
- Gradients on the shield are decorative. The lock glyph must still meet 3:1 against the shield
  body, and the shield must not be the only indicator of the verdict.

---

## 6. Typography and spacing

### 6.1 Type scale

Use the Material 3 type scale; do not invent a parallel system:
[m3.material.io/styles/typography/type-scale-tokens](https://m3.material.io/styles/typography/type-scale-tokens).

| Use | Token | Size / line height | Notes |
|---|---|---|---|
| Home hero title | `headlineMedium` | 28sp / 36sp | Sentence case; keep to two lines |
| Verdict label | `headlineSmall` or `titleLarge` | 24sp / 32sp or 22sp / 28sp | Use the smaller token on the result screen |
| Supporting sentence | `bodyLarge` | 16sp / 24sp | Minimum for primary explanations |
| Reason title | `titleSmall` | 14sp / 20sp, weight 600 | Short, 3–6 words |
| Reason body | `bodyMedium` | 14sp / 20sp | 4.5:1 minimum; avoid long paragraphs |
| Primary button | `labelLarge` | 14sp / 20sp, weight 600 | Full-width pill, 52–56dp high |
| Nav label | `labelMedium` | 12sp / 16sp | Always visible |
| Helper / legal | `bodySmall` | 12sp / 16sp | Never the only place for safety-critical information |

For older users, prefer 16sp for the main explanation even though M3 `bodyMedium` is 14sp. Keep
14sp for secondary metadata only. Avoid light/thin weights, all-caps, and italics; thin strokes
break down in Devanagari and Tamil, and all-caps does not apply cleanly to Indic scripts.

### 6.2 Spacing and shape

- 4dp base grid.
- Screen horizontal padding: 16dp on phones; 24dp on large screens, with content capped at 600dp.
- Card padding: 16–20dp. Hero card: 20–24dp.
- Vertical rhythm: 8dp inside a row, 12dp between related elements, 24dp between sections.
- Card corner radius: 16dp; hero card: 28dp; inputs: 12dp; buttons and chips: full pill.
  M3 shape scale: [m3.material.io/styles/shape/corner-radius-scale](https://m3.material.io/styles/shape/corner-radius-scale).
- Primary button: 52–56dp high, 24dp horizontal padding, full width on the result screen.
- Navigation bar: standard M3 height; 24dp icons; labels visible; selected icon filled.
- Minimum touch target: 48×48dp even when the visual icon is 24dp.
- Avoid nested cards. Use one card for the verdict, plain rows for reasons, and a single surface
  container for optional detail.
- Respect window insets and gesture navigation; never place the primary action under the nav bar.

### 6.3 Accessibility and motion

- Test at 200% font scaling and with TalkBack. Android 14+ uses nonlinear font scaling; do not
  clamp text or use fixed-height containers:
  [developer.android.com/about/versions/14/behavior-changes-14](https://developer.android.com/about/versions/14/behavior-changes-14).
- Android 15 enables `elegantTextHeight` by default for tall scripts including Tamil; still verify
  line height, clipping, and button labels:
  [developer.android.com/about/versions/15/behavior-changes-15](https://developer.android.com/about/versions/15/behavior-changes-15).
- Give the shield a content description only if it conveys meaning; otherwise mark it decorative.
  Announce the verdict as a single polite message, not the full SMS.
- Respect “Remove animations” / reduced motion. A glossy hero can be static; no parallax, looping
  shimmer, or pulsing red.
- Use icon + text for every state:
  - Safe: shield with check, green, “No scam signs found”.
  - Suspicious: shield with exclamation, amber, “Some scam signs”.
  - Dangerous: shield with warning, red, “Likely scam”.
- Do not use red for “Suspicious”; reserve red for likely scam and destructive actions.
- Provide haptic feedback only on primary action confirmation, not on every scroll or card.

### 6.4 Component choices

- **Cards:** use filled or outlined cards from Material 3, with 16dp radius and 16dp padding.
  The verdict hero is the only 28dp “extra large” card. Avoid nested cards and avoid elevated
  cards stacked on tinted surfaces; they add visual noise.
- **Buttons:** one filled pill for the primary action, text buttons for secondary actions, and an
  outlined button only for a genuine third option. M3 button guidance:
  [m3.material.io/components/buttons/overview](https://m3.material.io/components/buttons/overview).
- **Chips:** use filter chips only on Alerts; do not use chips as the main navigation. Keep the
  selected state to a tonal fill plus a check icon, not colour alone.
- **Inputs:** the paste field is a large filled text area with a visible label, 12dp radius, and
  at least 120dp height. Do not use a placeholder as the only label.
- **Dialogs:** reserve dialogs for destructive confirmation (“Clear history?”) and the
  “Report a mistake” reason picker. Do not use a dialog for the verdict; it hides context.
- **Bottom navigation colours:** use `surfaceContainer` for the bar, `secondaryContainer` for the
  selected indicator, `onSecondaryContainer` for the selected icon, `onSurface` for the selected
  label, and `onSurfaceVariant` for unselected items. Selected icon contrast is **12.86:1** light
  and **7.27:1** dark; unselected item contrast on the bar is **7.89:1** light and **9.65:1**
  dark; selected label contrast is **14.50:1** light and **13.08:1** dark.

### 6.5 Shield illustration

- Use one custom vector shield with a centred lock, not a photorealistic stock 3D object. It will
  stay crisp, theme correctly, and look consistent in Hindi and Tamil layouts.
- Suggested treatment: a magenta gradient from `primary` to a darker plum, a soft top-left white
  highlight (under 15% opacity), and a thin inner light edge. Keep the shadow soft and under 8dp;
  avoid heavy bevels and lens flares.
- The lock glyph must be high-contrast against the shield body (at least 3:1). A white lock on the
  mid-to-dark magenta body is safe; do not put the lock on the lightest highlight.
- Mark the illustration decorative and keep all meaning in the adjacent text. Do not put the
  verdict word inside the shield or inside any image.
- In dark theme, use the light primary `#FFAFD6` with a deeper plum body; do not simply invert the
  light illustration.

---

## 7. Localisation and content design

### 7.1 Hindi and Tamil layout

- Translate content, not just labels. Safety instructions must be reviewed by native speakers; do
  not ship machine-translated warnings for financial advice.
- Expect 30–50% string expansion. Buttons should wrap to two lines or grow vertically; never
  truncate “Check message”, “Open Messages”, or “Not a scam”.
- Devanagari needs room for matras above and below the baseline. Tamil has tall ascenders and
  descenders. Use 1.5–1.75 line height for body text and avoid tight fixed heights.
- Use Noto Sans Devanagari and Noto Sans Tamil, weights 400/500/600:
  [Noto Sans Devanagari](https://fonts.google.com/noto/specimen/Noto+Sans+Devanagari),
  [Noto Sans Tamil](https://fonts.google.com/noto/specimen/Noto+Sans+Tamil).
  Avoid thin weights and letter-spacing; both reduce legibility in Indic scripts.
- Test the longest strings at 200% font scale on a 360dp-wide screen: verdict label, primary
  button, reason body, nav labels, and permission dialog.
- Use Indian number grouping and the rupee symbol where needed. Keep “1930”, “OTP”, “KYC”, and
  “UPI” recognisable; add a short gloss on first use rather than translating them into obscurity.
- Provide an in-app language picker in addition to the Android 13+ per-app language setting. Label
  languages in their own script: English, हिन्दी, தமிழ்.
- Do not put text in the shield illustration or in screenshots. Text in images cannot scale,
  translate, or be read by screen readers.
- Tamil typography guidance and testing notes:
  [mugilan93.com/designing-ui-for-tamil-text](https://mugilan93.com/designing-ui-for-tamil-text/).

### 7.2 Plain-language rules

- Aim for short sentences and common words. Explain “phishing” as “a fake message that tries to
  steal your information”; explain “smishing” not at all unless the user asks.
- Use “you” and concrete verbs: “Do not tap the link”, “Call your bank”, “Delete the message”.
- Avoid absolutes: “likely”, “some signs”, “no common signs found”. Never “100% safe”.
- Put the most important instruction first. Do not bury it under background explanation.
- Use examples from Indian life: KYC update, delivery fee, electricity bill, job offer, loan
  approval, lottery prize, fake customer care, UPI request.
- Keep legal/privacy text in About; do not make it the first thing a worried user sees.

---

## 8. What not to show

### Hide from all normal users

- Risk scores, percentages, probabilities, confidence values, thresholds, weights, and “model
  certainty”.
- Classifier, model, rule, or feature names; rule IDs; embeddings; inference latency; token counts.
- URLs, domains, IP addresses, redirect chains, WHOIS, DNS, SSL, or certificate details.
- Sender metadata: SIM slot, message type, encoding, timestamps, raw headers, network state.
- Backend status, queue state, model download progress, local database paths, logs, stack traces,
  dataset names, version strings, build numbers.
- Technical jargon: “phishing”, “smishing”, “heuristic”, “classifier”, “inference”, “ONNX”, “LLM”,
  “embedding”, “false positive rate”.
- Absolute safety guarantees: “100% safe”, “virus-free”, “this is definitely a scam” when the
  system is uncertain.
- Full message content on the lock screen or in a notification by default.
- Ads, upsells, countdown timers, fake urgency, or “upgrade to see the result”.
- Legal disclaimers as the primary content. Put them in About and link from the result footer.

Current implementation note: the verdict card still renders `risk_score_format`. Remove that row
and let the verdict label plus at most three reasons carry the result.

### Show instead

- The verdict word and one-sentence meaning.
- Up to three plain-language reasons.
- One primary action and one or two quiet secondary actions.
- “What to do next” in two or three steps.
- Optional AI explanation, clearly labelled as generated and fallible.
- A collapsed message preview with links disabled.
- Feedback and “Report a mistake”.
- The 1930 helpline and cybercrime.gov.in link in Learn/Get help, not as a red alarm on every
  screen.

### Special case: AI explanation

The AI explanation is secondary evidence, not the verdict. It should never display model names,
prompts, token counts, or backend details. If the explanation is unavailable, hide the affordance;
do not show a technical error. If the explanation disagrees with the rule-based verdict, surface
“mixed signals” and advise caution rather than silently choosing one.

---

## 9. Sources

Accessed 16 Nov 2026. Vendor pages and Material guidance can change; re-check before
implementation.

### Material 3 and Android

1. Material 3 navigation bar: https://m3.material.io/components/navigation-bar/overview
2. Material 3 navigation bar guidelines: https://m3.material.io/components/navigation-bar/guidelines
3. Material 3 colour roles: https://m3.material.io/styles/color/roles
4. Material 3 corner-radius scale: https://m3.material.io/styles/shape/corner-radius-scale
5. Material 3 tone-based surfaces: https://m3.material.io/blog/tone-based-surface-color-m3
6. Material 3 type scale: https://m3.material.io/styles/typography/type-scale-tokens
7. Material 3 cards: https://m3.material.io/components/cards/overview
8. Material 3 buttons: https://m3.material.io/components/buttons/overview
9. Compose Material 3: https://developer.android.com/develop/ui/compose/designsystems/material3
10. Compose cards: https://developer.android.com/develop/ui/compose/components/card
11. Compose buttons: https://developer.android.com/develop/ui/compose/components/button
12. Android accessibility: https://developer.android.com/guide/topics/ui/accessibility/apps
13. Android 15 behaviour changes: https://developer.android.com/about/versions/15/behavior-changes-15
14. Android 14 behaviour changes (nonlinear font scaling): https://developer.android.com/about/versions/14/behavior-changes-14
15. Per-app language preferences: https://developer.android.com/guide/topics/resources/app-languages

### Accessibility and warning UX

16. WCAG 2.2 contrast minimum: https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html
17. WCAG 2.2 use of colour: https://www.w3.org/WAI/WCAG22/Understanding/use-of-color.html
18. WCAG 2.2 target size minimum: https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html
19. WCAG 2.2 non-text contrast: https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html
20. NN/g progressive disclosure: https://www.nngroup.com/articles/progressive-disclosure/
21. NN/g usability for senior citizens: https://www.nngroup.com/articles/usability-for-senior-citizens/
22. Microsoft warning message guidelines: https://learn.microsoft.com/en-us/windows/win32/uxguide/mess-warn
23. Google PAIR, explainability and trust: https://pair.withgoogle.com/chapter/explainability-trust/

### Consumer safety products

24. Truecaller caller-ID screen colours: https://www.truecaller.com/blog/features/what-do-the-different-caller-id-screen-colors-in-truecaller-mean
25. Google Messages Verified SMS and spam protection: https://blog.google/products-and-platforms/products/messages/safer-conversations-messages-verified-sms-and-spam-protection/
26. Google Messages privacy and spam detection: https://support.google.com/messages/answer/9327903
27. Google Messages spam reporting: https://support.google.com/messages/answer/7029021
28. Google Pixel Scam Detection: https://support.google.com/pixelphone/answer/16704479
29. Norton Genie / Scam Protection: https://us.norton.com/blog/online-scams/norton-genie
30. Bitdefender Scamio: https://www.bitdefender.com/en-us/consumer/scamio
31. Kaspersky Who Calls: https://support.kaspersky.com/WhoCalls/iOS1.19/en-US/174141.htm
32. Samsung Message Guard: https://docs.samsungknox.com/admin/fundamentals/whitepaper/samsung-knox-mobile-security/application-security/samsung-message-guard/

### India and localisation

33. Cybercrime portal: https://cybercrime.gov.in/
34. National Cyber Crime Reporting Portal: https://i4c.mha.gov.in/ncrp.aspx
35. Designing UI for Tamil text: https://mugilan93.com/designing-ui-for-tamil-text/
36. Noto Sans Devanagari: https://fonts.google.com/noto/specimen/Noto+Sans+Devanagari
37. Noto Sans Tamil: https://fonts.google.com/noto/specimen/Noto+Sans+Tamil
