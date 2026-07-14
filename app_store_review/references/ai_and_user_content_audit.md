# AI and user-content audit

AI and UGC can overlap, but evaluate them separately: a model integration creates data-sharing, disclosure, consent, safety, retention, and age considerations; a user-content surface creates filtering, reporting, blocking, moderation, contact, and abuse-response obligations.

## AI integration detection

Look for provider SDKs, model names, endpoints, gateway/proxy routes, request/response schemas, prompt construction, image/audio/file upload, vector/search services, moderation, logging, and configuration for OpenAI, Anthropic, Google, Apple, Azure, AWS, and other providers.

Detection rules:

- A dependency/provider name proves only that code is present, not that it ships, runs, sends data, or identifies the payload.
- A request builder or endpoint plus payload fields is stronger evidence; confirm the release path and runtime request when authorized.
- Do not print secrets, authorization headers, prompts containing personal data, or customer content.
- Treat a first-party proxy as a destination in the flow, then trace downstream processors through backend evidence rather than assuming the model provider.

## AI data-sharing and privacy

For each AI feature determine:

1. exact data that can leave the device, including user input, account/context/history, files/images/audio, diagnostics, identifiers, location, and derived content;
2. direct and downstream recipient(s);
3. purpose, trigger, retention, training/use controls, region, access, and deletion behavior;
4. whether any payload is personal data under the app's actual context;
5. disclosure shown before transfer and whether explicit permission is obtained when Guideline 5.1.2 applies;
6. deny/withdraw behavior and whether the feature sends nothing before a required choice;
7. consistency with Privacy Policy, App Privacy, account/data deletion, and provider/backend contracts.

Guideline 5.1.2 now explicitly addresses sharing personal data with third parties, including third-party AI. Apply it only after proving or reasonably supporting the relevant transfer. HIG Generative AI provides design/privacy guidance; label it as guidance, not an independent rejection rule.

Sources: `ARG-5.1.2`, `ARG-5.1.1`, `HIG-GENERATIVE-AI`, `ASC-APP-PRIVACY`.

## AI content safety and age

Review, according to feature and audience:

- input/output moderation, policy enforcement, reporting/escalation, and safe failure states;
- harmful, sexual, hateful, violent, self-harm, illegal, medical/financial, impersonation, and privacy-sensitive output handling;
- disclosure of AI behavior and uncertainty where material to user decisions;
- child/teen access, age-gating, parental controls, and App Store age-rating answers;
- generated content that users publish or exchange, which may also be UGC/creator content;
- retention/deletion of prompts, outputs, uploaded media, embeddings, and moderation records.

Do not claim Apple mandates a particular model, moderation vendor, disclaimer wording, or universal age limit without a current official source. Link concrete safety failures to the applicable guideline context; otherwise present them as product/manual risks.

## UGC applicability

Treat posts, comments, profiles/bios, public/private chat, photos, video/audio, reviews, groups/communities, shared model outputs, creator feeds, and other user-published material as potential UGC. Confirm whether content is transmitted, visible to others, and controllable by users.

## UGC controls

For applicable UGC surfaces, verify end to end:

- method to prevent/filter objectionable material appropriate to the medium;
- reachable report mechanism tied to the specific content/user;
- timely response/moderation workflow, not merely a decorative UI control;
- ability to block abusive users and the resulting visibility/contact behavior;
- published support/contact information;
- user agreement and rules defining prohibited content/conduct;
- removal, appeal/escalation, repeat-abuse, evidence retention, and emergency processes as appropriate;
- creator-content age controls where content can exceed the app's age rating;
- age-rating answers that reflect chat, social/UGC, unrestricted access, and actual content exposure.

Sources: `ARG-1.2`, `ASC-AGE-RATING`.

## Manual abuse and consent tests

1. AI: deny consent and confirm no applicable personal-data transfer; allow and inspect named recipient/payload; delete history/account and verify intended deletion.
2. AI: test empty, malformed, slow, unavailable, unsafe, and over-limit responses; verify the UI never hangs or exposes raw provider errors/secrets.
3. UGC: create representative prohibited content; verify filtering or review behavior.
4. UGC: report content/user; verify acknowledgment and operational moderation path.
5. UGC: block a user; verify messages/profile/content and future contact behavior across accounts/devices.
6. UGC: open support/contact and terms without authentication where intended.
7. Age: test restricted/creator content and compare actual exposure with the App Store Connect rating.

Without backend/admin access, moderation service levels, downstream AI processor information, or runtime network evidence, mark those controls `Not verified`. Missing source keywords may justify `Possible` findings only; backend or framework code can implement the behavior elsewhere.
