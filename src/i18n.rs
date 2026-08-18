//! Minimal server-side i18n for the public pages. Mirrors the warren-website
//! language set (English, French, Romanian) and picks the language from the
//! browser's `Accept-Language` header, English by default.

/// A supported page language.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    /// English (default).
    En,
    /// French.
    Fr,
    /// Romanian.
    Ro,
}

impl Lang {
    /// Picks the best supported language from an `Accept-Language` header value
    /// (standard `en-US,fr;q=0.8` grammar), honoring q-weights. Unknown or
    /// missing headers fall back to English.
    #[must_use]
    pub(crate) fn from_accept_language(header: Option<&str>) -> Self {
        let Some(header) = header else {
            return Lang::En;
        };
        let mut best: Option<(f32, Lang)> = None;
        for part in header.split(',') {
            let mut it = part.split(';');
            let tag = it.next().unwrap_or("").trim().to_ascii_lowercase();
            // Primary subtag only ("fr-CA" -> "fr").
            let primary = tag.split('-').next().unwrap_or("");
            let lang = match primary {
                "fr" => Lang::Fr,
                "ro" => Lang::Ro,
                "en" => Lang::En,
                _ => continue,
            };
            // Parse the optional q-weight; default 1.0 per RFC 9110.
            let q = it
                .find_map(|p| p.trim().strip_prefix("q=").map(str::to_owned))
                .and_then(|v| v.parse::<f32>().ok())
                .unwrap_or(1.0);
            if best.is_none_or(|(bq, _)| q > bq) {
                best = Some((q, lang));
            }
        }
        best.map_or(Lang::En, |(_, l)| l)
    }

    /// The BCP-47 code for the `<html lang>` attribute.
    #[must_use]
    pub(crate) fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Fr => "fr",
            Lang::Ro => "ro",
        }
    }
}

/// Best primary language subtag from an `Accept-Language` header, q-weighted,
/// with NO allowlist: unlike [`Lang::from_accept_language`] (our page copy),
/// this feeds the DiscourseConnect `locale` field, and Discourse supports far
/// more interface locales than we do; it validates and silently drops unknown
/// values on its side, so passing e.g. `de` through is both safe and better
/// for the user than clamping to English.
#[must_use]
pub(crate) fn preferred_locale_subtag(header: Option<&str>) -> Option<String> {
    let header = header?;
    let mut best: Option<(f32, String)> = None;
    for part in header.split(',') {
        let mut it = part.split(';');
        let tag = it.next().unwrap_or("").trim().to_ascii_lowercase();
        let primary = tag.split('-').next().unwrap_or("");
        // RFC 5646 primary subtags are 2-3 ASCII letters; anything else
        // (wildcards, junk) is skipped.
        if !(2..=3).contains(&primary.len()) || !primary.bytes().all(|b| b.is_ascii_lowercase()) {
            continue;
        }
        let q = it
            .find_map(|p| p.trim().strip_prefix("q=").map(str::to_owned))
            .and_then(|v| v.parse::<f32>().ok())
            .unwrap_or(1.0);
        if best.as_ref().is_none_or(|(bq, _)| q > *bq) {
            best = Some((q, primary.to_owned()));
        }
    }
    best.map(|(_, l)| l)
}

impl Lang {
    /// The full string table for this language.
    #[must_use]
    pub(crate) fn strings(self) -> Strings {
        match self {
            Lang::En => EN,
            Lang::Fr => FR,
            Lang::Ro => RO,
        }
    }
}

/// Every user-facing string of the public pages, one instance per language.
/// Values may contain trusted inline HTML (they are compile-time constants).
pub(crate) struct Strings {
    pub(crate) tagline: &'static str,
    // Approval page.
    pub(crate) a_tab: &'static str,
    pub(crate) a_label: &'static str,
    pub(crate) a_heading: &'static str,
    pub(crate) a_body: &'static str,
    pub(crate) a_button: &'static str,
    pub(crate) a_scan: &'static str,
    pub(crate) a_session: &'static str,
    pub(crate) a_expires: &'static str,
    pub(crate) a_waiting: &'static str,
    pub(crate) a_expired: &'static str,
    pub(crate) a_subscription: &'static str,
    pub(crate) a_cancelled: &'static str,
    pub(crate) a_clock: &'static str,
    // Attach-logs page.
    pub(crate) l_tab: &'static str,
    pub(crate) l_heading: &'static str,
    pub(crate) l_body: &'static str,
    pub(crate) l_expires: &'static str,
    pub(crate) l_expires_pre: &'static str,
    pub(crate) l_waiting: &'static str,
    /// Shown from the moment the app approved until the forum writes finish.
    pub(crate) l_processing: &'static str,
    pub(crate) l_done: &'static str,
    pub(crate) l_received: &'static str,
    pub(crate) l_expired: &'static str,
    pub(crate) l_cancelled: &'static str,
    // Transparency page.
    pub(crate) t_tab: &'static str,
    pub(crate) t_heading: &'static str,
    pub(crate) t_intro: &'static str,
    pub(crate) t_see_h: &'static str,
    pub(crate) t_col_party: &'static str,
    pub(crate) t_col_sees: &'static str,
    pub(crate) t_row1_party: &'static str,
    pub(crate) t_row1_sees: &'static str,
    pub(crate) t_row2_party: &'static str,
    pub(crate) t_row2_sees: &'static str,
    pub(crate) t_row3_party: &'static str,
    pub(crate) t_row3_sees: &'static str,
    pub(crate) t_stored: &'static str,
    pub(crate) t_ip_h: &'static str,
    pub(crate) t_ip_p: &'static str,
    pub(crate) t_ip_note: &'static str,
    pub(crate) t_cannot_h: &'static str,
    pub(crate) t_cannot_1: &'static str,
    pub(crate) t_cannot_2: &'static str,
    pub(crate) t_cannot_3: &'static str,
}

const EN: Strings = Strings {
    tagline: "A burrow, not footprints.",
    a_tab: "Warren forum sign-in",
    a_label: "Community forum",
    a_heading: "Sign in with your Warren app",
    a_body: "Approve this sign-in from the device where the Warren app holds your key. No email, no password: your app signs a one-time challenge.",
    a_button: "Open the Warren app",
    a_scan: "On another device? Scan this code:",
    a_session: "Session",
    a_expires: "expires in 5 minutes",
    a_waiting: "Waiting for approval\u{2026}",
    a_expired: "Session expired. Close this page and try again.",
    a_subscription: "Forum access requires a Warren subscription. This wallet has never subscribed.",
    a_cancelled: "Sign-in cancelled from the Warren app. You can close this page.",
    a_clock: "The clock of the device running the Warren app is off by more than a minute, so its signature was refused. Enable automatic date and time on that device, then try again.",
    l_tab: "Warren, attach your logs",
    l_heading: "Send your logs to the Warren staff",
    l_body: "Your Warren app will prepare a redacted problem report from its recent logs. You can review it in the app before approving. The report goes privately to the Warren staff and is linked to your forum topic; it never appears publicly.",
    l_expires: "expires in 30 minutes",
    l_expires_pre: "expires in 30 minutes",
    l_waiting: "Waiting for the report from your Warren app\u{2026}",
    l_processing: "Sending your logs to the staff\u{2026}",
    l_done: "Logs delivered to the staff. Taking you back to your topic\u{2026}",
    l_received: "Report received. Return to the forum tab: your report form is waiting for you there.",
    l_expired: "Session expired. Close this page and click the button on your topic again.",
    l_cancelled: "Sending cancelled from the Warren app. You can close this page.",
    t_tab: "Warren forum: transparency",
    t_heading: "How forum sign-in protects you",
    t_intro: "The Warren forum has <strong>no emails, no passwords, and never sees your IP address</strong>. You sign in by proving control of your Warren wallet key: the app signs a one-time challenge with Ed25519. Nothing to remember, nothing to leak.",
    t_see_h: "What each party can see",
    t_col_party: "Party",
    t_col_sees: "Sees",
    t_row1_party: "The forum (Discourse)",
    t_row1_sees: "your opaque handle (e.g. <code>lusab-babad-dovok</code>), a synthetic non-routable <code>.invalid</code> email, the constant address <code>0.0.0.0</code> instead of your IP, and your posts",
    t_row2_party: "Anyone reading the forum",
    t_row2_sees: "your handle and posts. The handle is derived with a keyed HMAC: it cannot be reversed or correlated with a Warren account address",
    t_row3_party: "Warren (this sign-in service)",
    t_row3_sees: "your wallet public key at login time, for as long as it takes to verify your signature. What is kept afterwards is a keyed hash (HMAC) of that address, next to your handle. Support can find your handle from an address you give them; the reverse is impossible",
    t_stored: "Stored at rest: one row per account, holding that keyed hash, your handle, and the dates of your first and last sign-in. Your wallet address is not in it. A row with no sign-in for two years is deleted automatically.",
    t_ip_h: "IP masking, verbatim edge configuration",
    t_ip_p: "The reverse proxy in front of the forum pins the forwarded address headers to a constant before any request reaches Discourse:",
    t_ip_note: "Discourse therefore stores <code>0.0.0.0</code> as every user's IP, including at account creation (verified end to end). Access logs are disabled on the forum vhost.",
    t_cannot_h: "What we deliberately cannot do",
    t_cannot_1: "Recover your account without your recovery phrase (non-custodial: no email reset).",
    t_cannot_2: "See your forum reading habits per IP (there is no per-user IP).",
    t_cannot_3: "Turn your handle back into your wallet address. No copy of your address is kept: the linkage row holds only a keyed hash, which cannot be reversed.",
};

const FR: Strings = Strings {
    tagline: "Un terrier, pas d'empreintes.",
    a_tab: "Connexion au forum Warren",
    a_label: "Forum communautaire",
    a_heading: "Connectez-vous avec votre application Warren",
    a_body: "Approuvez cette connexion depuis l'appareil o\u{f9} l'application Warren d\u{e9}tient votre cl\u{e9}. Aucun e-mail, aucun mot de passe : votre application signe un d\u{e9}fi \u{e0} usage unique.",
    a_button: "Ouvrir l'application Warren",
    a_scan: "Sur un autre appareil ? Scannez ce code :",
    a_session: "Session",
    a_expires: "expire dans 5 minutes",
    a_waiting: "En attente d'approbation\u{2026}",
    a_expired: "Session expir\u{e9}e. Fermez cette page et r\u{e9}essayez.",
    a_subscription: "L'acc\u{e8}s au forum n\u{e9}cessite un abonnement Warren. Ce portefeuille n'a jamais souscrit.",
    a_cancelled: "Connexion annul\u{e9}e depuis l'application Warren. Vous pouvez fermer cette page.",
    a_clock: "L'horloge de l'appareil qui ex\u{e9}cute l'application Warren est d\u{e9}cal\u{e9}e de plus d'une minute, sa signature a donc \u{e9}t\u{e9} refus\u{e9}e. Activez la date et l'heure automatiques sur cet appareil, puis r\u{e9}essayez.",
    l_tab: "Warren, joindre vos journaux",
    l_heading: "Envoyer vos journaux au staff Warren",
    l_body: "Votre application Warren va pr\u{e9}parer un rapport de probl\u{e8}me expurg\u{e9} \u{e0} partir de ses journaux r\u{e9}cents. Vous pourrez le v\u{e9}rifier dans l'application avant d'approuver. Le rapport est envoy\u{e9} en priv\u{e9} au staff Warren et reli\u{e9} \u{e0} votre sujet ; il n'appara\u{ee}t jamais publiquement.",
    l_expires: "expire dans 30 minutes",
    l_expires_pre: "expire dans 30 minutes",
    l_waiting: "En attente du rapport de votre application Warren\u{2026}",
    l_processing: "Envoi de vos journaux au staff\u{2026}",
    l_done: "Journaux transmis au staff. Retour \u{e0} votre sujet\u{2026}",
    l_received: "Rapport re\u{e7}u. Revenez \u{e0} l'onglet du forum : votre formulaire vous y attend.",
    l_expired: "Session expir\u{e9}e. Fermez cette page et cliquez \u{e0} nouveau sur le bouton de votre sujet.",
    l_cancelled: "Envoi annul\u{e9} depuis l'application Warren. Vous pouvez fermer cette page.",
    t_tab: "Forum Warren : transparence",
    t_heading: "Comment la connexion au forum vous prot\u{e8}ge",
    t_intro: "Le forum Warren n'a <strong>aucun e-mail, aucun mot de passe, et ne voit jamais votre adresse IP</strong>. Vous vous connectez en prouvant que vous contr\u{f4}lez la cl\u{e9} de votre portefeuille Warren : l'application signe un d\u{e9}fi \u{e0} usage unique avec Ed25519. Rien \u{e0} retenir, rien \u{e0} fuiter.",
    t_see_h: "Ce que chaque partie peut voir",
    t_col_party: "Partie",
    t_col_sees: "Voit",
    t_row1_party: "Le forum (Discourse)",
    t_row1_sees: "votre pseudonyme opaque (ex. <code>lusab-babad-dovok</code>), un e-mail synth\u{e9}tique non routable en <code>.invalid</code>, l'adresse constante <code>0.0.0.0</code> \u{e0} la place de votre IP, et vos messages",
    t_row2_party: "Toute personne lisant le forum",
    t_row2_sees: "votre pseudonyme et vos messages. Le pseudonyme est d\u{e9}riv\u{e9} par un HMAC \u{e0} cl\u{e9} : il ne peut \u{ea}tre invers\u{e9} ni corr\u{e9}l\u{e9} avec une adresse de compte Warren",
    t_row3_party: "Warren (ce service de connexion)",
    t_row3_sees: "la cl\u{e9} publique de votre portefeuille au moment de la connexion, le temps de v\u{e9}rifier votre signature. Ce qui est conserv\u{e9} ensuite est une empreinte \u{e0} cl\u{e9} (HMAC) de cette adresse, \u{e0} c\u{f4}t\u{e9} de votre pseudonyme. Le support peut retrouver votre pseudonyme \u{e0} partir d'une adresse que vous lui donnez ; l'inverse est impossible",
    t_stored: "Conserv\u{e9} au repos : une ligne par compte, contenant cette empreinte \u{e0} cl\u{e9}, votre pseudonyme, et les dates de votre premi\u{e8}re et de votre derni\u{e8}re connexion. Votre adresse de portefeuille n'y figure pas. Une ligne sans connexion pendant deux ans est supprim\u{e9}e automatiquement.",
    t_ip_h: "Masquage d'IP, configuration exacte du proxy",
    t_ip_p: "Le reverse proxy devant le forum fixe les en-t\u{ea}tes d'adresse transmis \u{e0} une constante avant qu'aucune requ\u{ea}te n'atteigne Discourse :",
    t_ip_note: "Discourse enregistre donc <code>0.0.0.0</code> comme IP de chaque utilisateur, y compris \u{e0} la cr\u{e9}ation du compte (v\u{e9}rifi\u{e9} de bout en bout). Les journaux d'acc\u{e8}s sont d\u{e9}sactiv\u{e9}s sur le vhost du forum.",
    t_cannot_h: "Ce que nous ne pouvons d\u{e9}lib\u{e9}r\u{e9}ment pas faire",
    t_cannot_1: "R\u{e9}cup\u{e9}rer votre compte sans votre phrase de r\u{e9}cup\u{e9}ration (non-custodial : pas de r\u{e9}initialisation par e-mail).",
    t_cannot_2: "Voir vos habitudes de lecture du forum par IP (il n'y a pas d'IP par utilisateur).",
    t_cannot_3: "Retransformer votre pseudonyme en adresse de portefeuille. Aucune copie de votre adresse n'est conserv\u{e9}e : la ligne de liaison ne contient qu'une empreinte \u{e0} cl\u{e9}, qui ne s'inverse pas.",
};

const RO: Strings = Strings {
    tagline: "O vizuin\u{103}, nu urme.",
    a_tab: "Autentificare pe forumul Warren",
    a_label: "Forumul comunit\u{103}\u{21b}ii",
    a_heading: "Autentific\u{103}-te cu aplica\u{21b}ia Warren",
    a_body: "Aprob\u{103} aceast\u{103} autentificare de pe dispozitivul pe care aplica\u{21b}ia Warren \u{21b}i-\u{103} de\u{21b}ine cheia. F\u{103}r\u{103} e-mail, f\u{103}r\u{103} parol\u{103}: aplica\u{21b}ia semneaz\u{103} o provocare unic\u{103}.",
    a_button: "Deschide aplica\u{21b}ia Warren",
    a_scan: "Pe alt dispozitiv? Scaneaz\u{103} acest cod:",
    a_session: "Sesiune",
    a_expires: "expir\u{103} \u{ee}n 5 minute",
    a_waiting: "Se a\u{219}teapt\u{103} aprobarea\u{2026}",
    a_expired: "Sesiune expirat\u{103}. \u{ce}nchide aceast\u{103} pagin\u{103} \u{219}i \u{ee}ncearc\u{103} din nou.",
    a_subscription: "Accesul la forum necesit\u{103} un abonament Warren. Acest portofel nu a avut niciodat\u{103} un abonament.",
    a_cancelled: "Autentificare anulat\u{103} din aplica\u{21b}ia Warren. Po\u{21b}i \u{ee}nchide aceast\u{103} pagin\u{103}.",
    a_clock: "Ceasul dispozitivului care ruleaz\u{103} aplica\u{21b}ia Warren este decalat cu mai mult de un minut, a\u{219}a c\u{103} semn\u{103}tura a fost refuzat\u{103}. Activeaz\u{103} data \u{219}i ora automate pe acel dispozitiv, apoi \u{ee}ncearc\u{103} din nou.",
    l_tab: "Warren, ata\u{219}eaz\u{103}-\u{21b}i jurnalele",
    l_heading: "Trimite jurnalele c\u{103}tre echipa Warren",
    l_body: "Aplica\u{21b}ia Warren va preg\u{103}ti un raport de problem\u{103} anonimizat din jurnalele sale recente. \u{ce}l po\u{21b}i verifica \u{ee}n aplica\u{21b}ie \u{ee}nainte de a aproba. Raportul este trimis privat echipei Warren \u{219}i legat de subiectul t\u{103}u; nu apare niciodat\u{103} public.",
    l_expires: "expir\u{103} \u{ee}n 30 de minute",
    l_expires_pre: "expir\u{103} \u{ee}n 30 de minute",
    l_waiting: "Se a\u{219}teapt\u{103} raportul din aplica\u{21b}ia Warren\u{2026}",
    l_processing: "Trimitem jurnalele dumneavoastr\u{103} c\u{103}tre echip\u{103}\u{2026}",
    l_done: "Jurnale transmise echipei. Te ducem \u{ee}napoi la subiectul t\u{103}u\u{2026}",
    l_received: "Raport primit. Revino la fila forumului: formularul t\u{103}u te a\u{219}teapt\u{103} acolo.",
    l_expired: "Sesiune expirat\u{103}. \u{ce}nchide aceast\u{103} pagin\u{103} \u{219}i apas\u{103} din nou butonul de pe subiect.",
    l_cancelled: "Trimitere anulat\u{103} din aplica\u{21b}ia Warren. Po\u{21b}i \u{ee}nchide aceast\u{103} pagin\u{103}.",
    t_tab: "Forumul Warren: transparen\u{21b}\u{103}",
    t_heading: "Cum te protejeaz\u{103} autentificarea pe forum",
    t_intro: "Forumul Warren nu are <strong>niciun e-mail, nicio parol\u{103} \u{219}i nu \u{21b}i-\u{103} vede niciodat\u{103} adresa IP</strong>. Te autentifici dovedind c\u{103} de\u{21b}ii cheia portofelului t\u{103}u Warren: aplica\u{21b}ia semneaz\u{103} o provocare unic\u{103} cu Ed25519. Nimic de re\u{21b}inut, nimic de scurs.",
    t_see_h: "Ce poate vedea fiecare parte",
    t_col_party: "Parte",
    t_col_sees: "Vede",
    t_row1_party: "Forumul (Discourse)",
    t_row1_sees: "pseudonimul t\u{103}u opac (ex. <code>lusab-babad-dovok</code>), un e-mail sintetic nerutabil <code>.invalid</code>, adresa constant\u{103} <code>0.0.0.0</code> \u{ee}n locul IP-ului t\u{103}u, \u{219}i mesajele tale",
    t_row2_party: "Oricine cite\u{219}te forumul",
    t_row2_sees: "pseudonimul \u{219}i mesajele tale. Pseudonimul este derivat printr-un HMAC cu cheie: nu poate fi inversat sau corelat cu o adres\u{103} de cont Warren",
    t_row3_party: "Warren (acest serviciu de autentificare)",
    t_row3_sees: "cheia public\u{103} a portofelului t\u{103}u \u{ee}n momentul autentific\u{103}rii, c\u{e2}t dureaz\u{103} verificarea semn\u{103}turii. Ceea ce se p\u{103}streaz\u{103} apoi este o amprent\u{103} cu cheie (HMAC) a acelei adrese, al\u{103}turi de pseudonimul t\u{103}u. Echipa de suport poate g\u{103}si pseudonimul pornind de la o adres\u{103} pe care i-o dai tu; invers este imposibil",
    t_stored: "Stocat pe termen lung: un r\u{e2}nd per cont, care con\u{21b}ine acea amprent\u{103} cu cheie, pseudonimul t\u{103}u \u{219}i datele primei \u{219}i ultimei autentific\u{103}ri. Adresa portofelului t\u{103}u nu se afl\u{103} acolo. Un r\u{e2}nd f\u{103}r\u{103} autentificare timp de doi ani este \u{219}ters automat.",
    t_ip_h: "Mascarea IP, configura\u{21b}ia exact\u{103} a proxy-ului",
    t_ip_p: "Reverse proxy-ul din fa\u{21b}a forumului fixeaz\u{103} anteturile de adres\u{103} transmise la o constant\u{103} \u{ee}nainte ca vreo cerere s\u{103} ajung\u{103} la Discourse:",
    t_ip_note: "Prin urmare, Discourse stocheaz\u{103} <code>0.0.0.0</code> ca IP al fiec\u{103}rui utilizator, inclusiv la crearea contului (verificat de la cap la cap). Jurnalele de acces sunt dezactivate pe vhost-ul forumului.",
    t_cannot_h: "Ce nu putem face \u{ee}n mod deliberat",
    t_cannot_1: "S\u{103} \u{21b}i recuper\u{103}m contul f\u{103}r\u{103} fraza ta de recuperare (non-custodial: nicio resetare prin e-mail).",
    t_cannot_2: "S\u{103} vedem obiceiurile tale de citire pe forum pe IP (nu exist\u{103} IP per utilizator).",
    t_cannot_3: "S\u{103} transform\u{103}m pseudonimul \u{ee}napoi \u{ee}n adresa portofelului. Nicio copie a adresei tale nu este p\u{103}strat\u{103}: r\u{e2}ndul de leg\u{103}tur\u{103} con\u{21b}ine doar o amprent\u{103} cu cheie, care nu poate fi inversat\u{103}.",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_unknown_header_is_english() {
        assert_eq!(Lang::from_accept_language(None), Lang::En);
        assert_eq!(Lang::from_accept_language(Some("de,es;q=0.5")), Lang::En);
    }

    #[test]
    fn primary_subtag_matches() {
        assert_eq!(Lang::from_accept_language(Some("fr-CA")), Lang::Fr);
        assert_eq!(Lang::from_accept_language(Some("ro-RO,ro")), Lang::Ro);
    }

    #[test]
    fn q_weights_pick_the_highest() {
        // English is listed first but French outweighs it.
        assert_eq!(
            Lang::from_accept_language(Some("en;q=0.5, fr;q=0.9")),
            Lang::Fr
        );
        // An unknown high-q language is skipped in favor of a supported one.
        assert_eq!(
            Lang::from_accept_language(Some("de;q=1.0, ro;q=0.4")),
            Lang::Ro
        );
    }

    #[test]
    fn locale_subtag_passes_any_language_through() {
        // Unlike the page copy, the SSO locale is not clamped to en/fr/ro.
        assert_eq!(
            preferred_locale_subtag(Some("de-DE,de;q=0.9")),
            Some("de".to_owned())
        );
        assert_eq!(
            preferred_locale_subtag(Some("en;q=0.5, fr;q=0.9")),
            Some("fr".to_owned())
        );
    }

    #[test]
    fn locale_subtag_rejects_junk_and_missing() {
        assert_eq!(preferred_locale_subtag(None), None);
        assert_eq!(preferred_locale_subtag(Some("*;q=0.1, !!,")), None);
    }
}
