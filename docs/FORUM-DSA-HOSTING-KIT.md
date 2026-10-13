# Forum DSA hosting kit

The support forum (`forum.warrenbrowse.com`) stores what subscribers post and
the problem reports they deposit, on a server Warren rents. Under the Digital
Services Act (Regulation (EU) 2022/2065) that makes Warren a hosting provider
for the forum, on top of the mere-conduit VPN. Decision of poka, 13 October
2026, recorded in the workspace report
`RAPPORT-CONFORMITE-ROUMANIE-LEXTER-2026-10-13.md` (v1.3, sections 1 and 3.4).

warrenBrowse is a micro enterprise (same report, section 1), so the online
platform obligations of DSA Section 3 do not apply (art. 19). What applies to
every hosting provider, whatever its size: the notice-and-action mechanism
(art. 16), the statement of reasons (art. 17), and the notification of
suspected criminal offences threatening life or safety (art. 18). The terms
must state the usage restrictions (art. 14).

This kit is the text and the specification to put in place. Nothing here is
deployed by an agent: the forum is administered by poka.

## 1. Operator step: disable user-to-user private messages

The report declares to Lexter that users cannot message each other (memo
II.3(f)). Discourse allows it by default.

In the Discourse admin, Settings, search `personal message enabled groups` and
set it to `staff` only (Discourse 3.x name; check it on the instance before the
change). Staff and the system account keep sending private messages: the staff
log inbox and the reporter's receipt rely on them. Check afterwards, with an
ordinary account, that the "Message" button is gone from another user's card,
and that a reporter can still read and answer the receipt PM sent to them (not
verified on this instance).

## 2. Forum terms

Published as a pinned topic in the site-feedback category and linked from the
forum footer. The Warren terms (CGU) stay the contract; these terms add the
forum-specific rules.

### Français

> **Conditions d'utilisation du forum Warren**
>
> Ce forum sert au support du service Warren. Il est exploité par
> warrenBrowse SRL, [siège], qui en héberge le contenu.
>
> Il est interdit d'y publier : un contenu illicite au regard du droit de
> l'Union ou du droit roumain ; des données personnelles d'un tiers ; des
> clés, mots de passe ou phrases de récupération ; de la publicité ; des
> contenus qui incitent à utiliser Warren pour commettre une infraction.
>
> Tout le monde peut signaler un contenu par le bouton « Signaler » ou par le
> formulaire de signalement (lien). Chaque signalement reçoit un accusé de
> réception. L'équipe Warren examine le signalement avec diligence et
> objectivité, et informe son auteur de la décision.
>
> L'équipe peut retirer un contenu, le masquer, ou suspendre un compte du
> forum. L'auteur reçoit un message qui explique la mesure, son motif et ses
> voies de recours. Les décisions sont prises par une personne ; aucun outil
> automatique ne retire de contenu.
>
> Les journaux de diagnostic déposés depuis l'application sont visibles de
> l'équipe support seulement et sont supprimés après 12 mois. Les messages
> privés entre utilisateurs sont désactivés.
>
> Contact : contact@warrenbrowse.com. Autorités : legal@warrenbrowse.com.

### English

> **Warren forum terms**
>
> This forum supports the Warren service. It is operated by warrenBrowse SRL,
> [seat], which hosts its content.
>
> You may not post: content that is illegal under EU or Romanian law;
> personal data of a third party; keys, passwords or recovery phrases;
> advertising; content that encourages using Warren to commit an offence.
>
> Anyone can report content with the "Flag" button or the reporting form
> (link). Every report is acknowledged. The Warren team reviews it diligently
> and objectively and tells the reporter what it decided.
>
> The team may remove or hide content, or suspend a forum account. The
> author receives a message giving the measure, its reason and the available
> redress. Decisions are taken by a person; no automated tool removes
> content.
>
> Diagnostic logs deposited from the app are visible to the support team only
> and are deleted after 12 months. Private messages between users are
> disabled.
>
> Contact: contact@warrenbrowse.com. Authorities: legal@warrenbrowse.com.

### Română

> **Condițiile de utilizare a forumului Warren**
>
> Acest forum servește asistenței pentru serviciul Warren. Este operat de
> warrenBrowse SRL, [sediu], care găzduiește conținutul său.
>
> Este interzisă publicarea de: conținut ilegal conform dreptului Uniunii
> sau dreptului român; date personale ale unei terțe persoane; chei, parole
> sau fraze de recuperare; publicitate; conținut care încurajează folosirea
> Warren pentru a comite o infracțiune.
>
> Oricine poate semnala un conținut prin butonul „Semnalează" sau prin
> formularul de semnalare (link). Fiecare semnalare primește o confirmare de
> primire. Echipa Warren o examinează cu diligență și obiectivitate și îi
> comunică autorului decizia.
>
> Echipa poate elimina sau ascunde un conținut ori suspenda un cont de pe
> forum. Autorul primește un mesaj care explică măsura, motivul ei și căile
> de atac. Deciziile sunt luate de o persoană; niciun instrument automat nu
> elimină conținut.
>
> Jurnalele de diagnosticare depuse din aplicație sunt vizibile doar echipei
> de asistență și sunt șterse după 12 luni. Mesajele private între
> utilizatori sunt dezactivate.
>
> Contact: contact@warrenbrowse.com. Autorități: legal@warrenbrowse.com.

## 3. Notice-and-action form (art. 16)

A public form, reachable without an account, linked from the forum footer and
from the terms. Discourse's own "Flag" button stays available to members; the
form covers non-members and every report that must carry the art. 16(2)
elements.

Fields (art. 16(2)):

| field | required | note |
|---|---|---|
| URL of the content | yes | the exact post link |
| explanation of why the content is illegal | yes | free text |
| name of the notifier | yes, except for offences under Directive 2011/93/EU (child sexual abuse) | |
| email of the notifier | yes, same exception | used only to answer this notice |
| statement of good faith | yes | checkbox: "I am convinced in good faith that the information in this notice is accurate and complete" |

Handling:

1. Automatic acknowledgement to the notifier's email (art. 16(4)).
2. Each notice lands in a staff-only queue (a Discourse group inbox or the
   `abuse@` mailbox), with the date and the decision taken, and nothing about
   the notifier beyond what the notice holds.
3. The gérant decides (report v1.3, section 1). Notices are processed in a
   timely, diligent, non-arbitrary and objective manner (art. 16(6)).
4. The notifier is told the decision and the available redress (art. 16(5)).
5. Notices and decisions are kept 12 months, as the deposited logs, then
   deleted.

Implementation choice still to make by the person building it: a page on
`warren-connect` (which already serves forms without a tracking surface) or
the website. Either way the form loads nothing from a third party, like the
rest of the forum.

## 4. Statement of reasons template (art. 17)

Sent to the author of any removed, hidden or restricted content, or of a
suspended account, at the latest when the measure is applied (art. 17(2)).
Delivered as a Discourse private message from the staff account.

> **Votre contenu sur le forum Warren / Your content on the Warren forum**
>
> - Measure: [removal / hiding / account suspension until <date>]
> - Content concerned: [link or quote]
> - Facts and circumstances: [what was found, and whether it came from a
>   notice (art. 16) or from the team's own review]
> - Automated means: none; the decision was taken by a person.
> - Ground: [the legal provision, if the content is illegal, with the reason
>   it is] or [the clause of the forum terms it breaches, with the reason it
>   does]
> - Redress: you can contest this decision by writing to
>   contact@warrenbrowse.com, and you can bring it before the competent
>   Romanian courts.

The template is kept in the three languages (fr, en, ro); the message is sent
in the language the author writes in.

## 5. Suspected offences threatening life or safety (art. 18)

When the team becomes aware of information giving rise to a suspicion that a
criminal offence involving a threat to the life or safety of a person has
taken place, is taking place or is likely to take place, it informs the
authorities promptly, with all the relevant information available.

1. Who: the gérant, or anyone on the team who sees it first if the gérant
   cannot be reached within the hour.
2. To whom: the law enforcement or judicial authorities of the Member State
   concerned (the place of the offence, of the suspect or of the victim, when
   known). In Romania, the Poliția Română emergency line 112 for an imminent
   threat. When the Member State cannot be identified, Europol.
3. What: the forum content (link and copy), its date, the public pseudonym,
   and what the team knows. Nothing more is collected for the occasion.
4. Record: the date, the authority informed and the content concerned, in the
   escalation register (`warren-core/docs/NN-ABUSE-ESCALATION.md` when it
   exists).

## 6. Retention on the forum side

- Deposited problem reports: the staff PM carrying the uploaded log gets a
  Discourse deletion timer 12 months out when it is created
  (`LOG_RETENTION_DAYS`, `src/attach.rs`; `ForumApi::schedule_deletion`).
  Discourse's delete is a soft delete. The operator's yearly pass removes
  deleted log topics for good and checks that Discourse's orphan-upload
  cleanup took the files (not verified on this instance). Reports delivered
  before this change carry no timer and are removed by that pass.
- Wallet-to-pseudonym link: a wallet removes its own link with the signed
  `POST /v1/forum/unlink`. Inactive links go after 730 days
  (`FORUM_LINK_RETENTION_DAYS`).
- Account deletion: warren-core's account deletion does not call
  warren-connect today, so deleting a Warren account leaves its forum link in
  place until the 730-day sweep. The app should call `POST /v1/forum/unlink`
  with the same wallet before it deletes the account.
