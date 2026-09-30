# Account-Existence Platforms

MailAccess ships a native **account-existence engine**: given an email address, it
determines whether that address has a registered account on a service, using only
the service's own publicly-observable authentication behaviour. It runs as part of
the `account_discovery` step of `mailaccess investigate`, with **no third-party
API keys and no runtime dependencies**.

As of 0.18.0 the catalogue covers **357 email-checkable services** — consumer apps,
SaaS and developer tools, and community forums. This page lists every one and the
method used for it.

## What "checking" means

Each service leaks account existence through one publicly-reachable endpoint. The
engine sends a single request and reads the response for a decisive signal. The
methods, from least to most sensitive:

- **Signup availability** — submit the email to a registration/validation endpoint;
  the service reports whether the address is already taken. *No email is sent.*
- **Login-error differential** — attempt a login with a deliberately wrong password.
  A response of "no account with that email" versus "incorrect password"
  distinguishes a registered address from an unknown one. *No email is sent.*
- **Account-recovery search** — a recovery wizard reports whether any account
  matches the address. *No email is sent.*
- **Signup-validation API** — a public validation endpoint returns whether the
  address is already associated with an account. *No email is sent.*
- **Key-directory lookup** — a public key/profile directory returns a record for
  the address. *No email is sent.*
- **Password-reset differential** — a reset form returns a distinct "no account
  found" message for an unknown address. Because submitting a *registered* address
  triggers a real reset email, these are marked **intrusive** and are **off by
  default** — enable with `ENABLE_FORGOT_PASSWORD_PROBES=true` for authorized,
  consented testing only. Only oracles that expose a reliable negative ("no account
  found") marker are included; positive "we sent you a reset" pages are rejected as
  unreliable.

## Honesty and safety

- **Default-on checks send no email.** Every method except the gated
  password-reset differential is non-intrusive.
- **Verdicts are explicit:** `exists`, `absent`, `rate_limited` (the service
  throttled us), `transport_error` (DNS/timeout/TLS — not the platform's fault),
  or `inconclusive`. Transport failures are never mislabelled as rate-limiting.
- **Findings are leads, not proof.** A positive result is surfaced as an unverified,
  medium-confidence "email registration signal" — never a confirmed account.
- The account-existence technique is decaying industry-wide as services harden their
  auth flows; this catalogue reflects the services that still expose a reliable,
  non-intrusive signal.

## Browser tier (optional)

Some platforms only reveal existence through a JavaScript-driven flow, or sit behind
Cloudflare where a plain HTTP request is blocked. Installing the optional browser
extra adds a headless-browser oracle tier (Playwright + stealth):

```bash
pip install "mailaccess[browser]" && playwright install chromium
```

It contributes **email-first** login oracles and **forgot-password** oracles for
JS-only flows, and can run the XenForo forum checks through a real browser to get
past Cloudflare. Email-first oracles send no email and run when the extra is
installed; the full XenForo browser sweep is opt-in via `ENABLE_BROWSER_XENFORO=true`.
Default installs are unaffected — the browser code is imported lazily.

---

<!-- GENERATED: do not hand-edit tables below; regenerate from the catalogue. -->

## Consumer, SaaS &amp; developer services (201)

| Platform | Domain | Category | Check method |
|---|---|---|---|
| FapFolder | fapfolder.club | adult | Signup availability |
| FapRoulette | faproulette.co | adult | Signup availability |
| LetsPorn | letsporn.com | adult | Signup availability |
| Lovescape | lovescape.com | adult | Signup availability |
| SuperPorn | superporn.com | adult | Signup availability |
| TheGay | thegay.com | adult | Signup availability |
| Atlassian | atlassian.com | cms | Login-error differential |
| Gravatar | en.gravatar.com | cms | Existence probe |
| Voxmedia | voxmedia.com | cms | Signup availability |
| Wordpress | wordpress.com | cms | Login-error differential |
| Disqus | disqus.com | community | Signup availability |
| Nextdoor | nextdoor.com | community | Login-error differential |
| Stack Overflow | stackoverflow.com | community | Login-error differential |
| Aboutme | about.me | company | Signup availability |
| Canva | canva.com | creator | Login-error differential |
| Figma | figma.com | creator | Signup availability |
| Gumroad | gumroad.com | creator | Signup availability |
| Kick | kick.com | creator | Signup availability |
| Leanpub | leanpub.com | creator | Signup availability |
| Vimeo | vimeo.com | creator | Signup availability |
| Amocrm | amocrm.com | crm | Signup availability |
| Axonaut | axonaut.com | crm | Signup availability |
| Hubspot | hubspot.com | crm | Login-error differential |
| Insightly | insightly.com | crm | Signup availability |
| Nimble | nimble.com | crm | Signup availability |
| Nocrm | nocrm.io | crm | Signup availability |
| Nutshell | nutshell.com | crm | Login-error differential |
| Pipedrive | pipedrive.com | crm | Signup availability |
| Teamleader | teamleader.eu | crm | Signup availability |
| Zoho | zoho.com | crm | Login-error differential |
| Buymeacoffee | buymeacoffee.com | crowdfunding | Signup availability |
| LesPark | lespark.cn | dating | Login-error differential |
| Locanto | locanto.org | dating | Signup availability |
| OkCupid | okcupid.com | dating | Existence probe |
| Skout | skout.com | dating | Signup availability |
| Codewars | www.codewars.com | dev | Signup availability |
| Hack The Box | account.hackthebox.com | dev | Signup availability |
| HackerEarth | www.hackerearth.com | dev | Signup availability |
| HackerOne | hackerone.com | dev | Signup availability |
| HackerRank | www.hackerrank.com | dev | Signup availability |
| How-To Geek | www.howtogeek.com | dev | Existence probe |
| Hugging Face | huggingface.co | dev | Signup availability |
| LuaRocks | luarocks.org | dev | Password-reset differential |
| Qiita | qiita.com | dev | Signup availability |
| RubyGems | rubygems.org | dev | Signup availability |
| Wix | users.wix.com | dev | Signup availability |
| Wondershare | accounts.wondershare.com | dev | Signup availability |
| XDA Developers | www.xda-developers.com | dev | Existence probe |
| Edx | edx.org | education | Signup-validation API |
| AniList | anilist.co | entertainment | Password-reset differential |
| Apple TV | tv.apple.com | entertainment | Login-error differential |
| Dreame | dreame.com | entertainment | Login-error differential |
| Girls' Life | girlslife.com | entertainment | Signup availability |
| Letterboxd | letterboxd.com | entertainment | Signup availability |
| MyAnimeList | myanimelist.net | entertainment | Signup availability |
| Nebula | nebula.tv | entertainment | Signup availability |
| Netflix | netflix.com | entertainment | Signup availability |
| Stremio | stremio.com | entertainment | Login-error differential |
| Sun NXT | sunnxt.com | entertainment | Existence probe |
| EvolveYou | evolveyou.app | fitness | Login-error differential |
| FitnessBlender | fitnessblender.com | fitness | Signup availability |
| MyFitnessPal | myfitnesspal.com | fitness | Signup availability |
| Sweat | sweat.com | fitness | Login-error differential |
| Kompas | kompas.com | forgot-password | Password-reset differential (intrusive, gated) |
| AddictingGames | addictinggames.com | gaming | Signup availability |
| Chess.com | chess.com | gaming | Signup availability |
| Medal.tv | medal.tv | gaming | Signup availability |
| Steam | steampowered.com | gaming | Account-recovery search |
| Femometer | femometer.com | health | Existence probe |
| Glow | glowing.com | health | Signup availability |
| MeetYou | meetyouintl.com | health | Existence probe |
| My Period Tracker | period-tracker.com | health | Existence probe |
| Premom | premom.com | health | Signup availability |
| WomanLog | womanlog.com | health | Login-error differential |
| Bunny.net | bunny.net | hosting | Signup availability |
| Neocities | neocities.org | hosting | Signup availability |
| Coroflot | coroflot.com | jobs | Signup availability |
| Freelancer | freelancer.com | jobs | Signup availability |
| Seoclerks | seoclerks.com | jobs | Signup availability |
| Alison | alison.com | learning | Signup availability |
| Allen | allen.in | learning | Existence probe |
| Annaabi | annaabi.ee | learning | Signup availability |
| ASL Bloom | aslbloom.com | learning | Existence probe |
| Babbel | babbel.com | learning | Signup availability |
| Cake | cakeapp.me | learning | Existence probe |
| ClassDojo | classdojo.com | learning | Existence probe |
| Coursera | coursera.org | learning | Existence probe |
| Diigo | diigo.com | learning | Signup availability |
| Duolingo | duolingo.com | learning | Signup availability |
| Quizlet | quizlet.com | learning | Signup availability |
| Vedantu | vedantu.com | learning | Login-error differential |
| Laposte | laposte.fr | mails | Signup availability |
| Mail Ru | mail.ru | mails | Password-reset differential |
| Protonmail | protonmail.com | mails | Key-directory lookup |
| Ello | ello.co | medias | Signup availability |
| Flickr | flickr.com | medias | Login-error differential |
| Komoot | komoot.com | medias | Login-error differential |
| Rambler | rambler.ru | medias | Login-error differential |
| Caringbridge | caringbridge.org | medical | Login-error differential |
| Sevencups | 7cups.com | medical | Signup availability |
| Blip | blip.fm | music | Signup availability |
| Deezer | deezer.com | music | Signup availability |
| Gaana | gaana.com | music | Login-error differential |
| JioSaavn | jiosaavn.com | music | Signup availability |
| Lastfm | last.fm | music | Signup availability |
| Mixcloud | mixcloud.com | music | Signup availability |
| Smule | smule.com | music | Signup availability |
| Spotify | spotify.com | music | Signup availability |
| Tunefind | tunefind.com | music | Signup availability |
| BBC | bbc.com | news | Login-error differential |
| CNN | cnn.com | news | Login-error differential |
| Flipboard | flipboard.com | news | Signup availability |
| Fox News | foxnews.com | news | Login-error differential |
| Global Times | globaltimes.cn | news | Login-error differential |
| The New York Times | nytimes.com | news | Login-error differential |
| Times of India | timesofindia.indiatimes.com | news | Login-error differential |
| Rocketreach | rocketreach.co | osint | Signup availability |
| DeviantArt | deviantart.com | other | Signup availability |
| DollarFix | dollarfix.com | other | Login-error differential |
| Dropbox | dropbox.com | other | Existence probe |
| Moz | moz.com | other | Signup availability |
| Numsify | numsify.com | other | Signup availability |
| Screener.in | screener.in | other | Signup availability |
| SecondLine (autobizline) | autobizline.com | other | Existence probe |
| Start.me | start.me | other | Signup availability |
| Venmo | venmo.com | payment | Signup availability |
| Pornhub | pornhub.com | porn | Signup availability |
| Redtube | redtube.com | porn | Signup availability |
| Xnxx | xnxx.com | porn | Signup availability |
| Xvideos | xvideos.com | porn | Signup availability |
| Anydo | any.do | productivity | Signup availability |
| Evernote | evernote.com | productivity | Login-error differential |
| Eventbrite | eventbrite.com | products | Login-error differential |
| Codecademy | codecademy.com | programing | Signup availability |
| Codepen | codepen.io | programing | Signup availability |
| Devrant | devrant.com | programing | Signup availability |
| Github | github.com | programing | Signup availability |
| Replit | replit.com | programing | Signup availability |
| Teamtreehouse | teamtreehouse.com | programing | Signup availability |
| Vrbo | vrbo.com | real_estate | Login-error differential |
| Armurerieauxerre | armurerie-auxerre.com | shopping | Signup availability |
| Deliveroo | deliveroo.com | shopping | Signup availability |
| Dominosfr | dominos.fr | shopping | Signup availability |
| Ebay | ebay.com | shopping | Login-error differential |
| Envato | envato.com | shopping | Signup availability |
| Etsy | etsy.com | shopping | Signup availability |
| Fixderma | fixderma.com | shopping | Signup availability |
| Flipkart | flipkart.com | shopping | Login-error differential |
| Garmin | garmin.com | shopping | Signup availability |
| Haute Sauce | buyhautesauce.com | shopping | Signup availability |
| Naturabuy | naturabuy.fr | shopping | Signup availability |
| Nike | nike.com | shopping | Signup availability |
| Nykaa Man | nykaaman.com | shopping | Signup availability |
| Rappi | rappi.com | shopping | Login-error differential |
| Tata CLiQ | tatadigital.com | shopping | Login-error differential |
| Tindie | tindie.com | shopping | Signup availability |
| Vivino | vivino.com | shopping | Login-error differential |
| Classmates | classmates.com | social_media | Login-error differential |
| Crevado | crevado.com | social_media | Signup availability |
| Discord | discord.com | social_media | Signup availability |
| Facebook | facebook.com | social_media | Signup availability |
| Fanpop | fanpop.com | social_media | Signup availability |
| Imgur | imgur.com | social_media | Signup availability |
| Instagram | instagram.com | social_media | Signup availability |
| Locket Widget | locketcamera.com | social_media | Login-error differential |
| Love Nudge | lovenudgeapp.com | social_media | Signup availability |
| MEEFF | meeff.com | social_media | Login-error differential |
| MeWe | mewe.com | social_media | Signup availability |
| Myspace | myspace.com | social_media | Signup availability |
| Odnoklassniki | ok.ru | social_media | Password-reset differential |
| Parler | parler.com | social_media | Login-error differential |
| Patreon | patreon.com | social_media | Signup availability |
| Pinterest | pinterest.com | social_media | Signup availability |
| Plurk | plurk.com | social_media | Signup availability |
| Taringa | taringa.net | social_media | Signup availability |
| Tellonym | tellonym.me | social_media | Signup availability |
| Twitter | twitter.com | social_media | Signup availability |
| Vsco | vsco.co | social_media | Signup availability |
| Wattpad | wattpad.com | social_media | Signup availability |
| Xing | xing.com | social_media | Signup availability |
| Adobe | adobe.com | software | Password-reset differential |
| Archive | archive.org | software | Signup availability |
| Docker | docker.com | software | Signup availability |
| Firefox | firefox.com | software | Login-error differential |
| Issuu | issuu.com | software | Signup availability |
| Lastpass | lastpass.com | software | Signup availability |
| Office365 | office365.com | software | Existence probe |
| AiScore | aiscore.com | sport | Signup availability |
| BeSoccer | besoccer.com | sport | Signup availability |
| Bodybuilding | bodybuilding.com | sport | Signup availability |
| ESPN | espn.com | sport | Signup availability |
| Marca | marca.com | sport | Existence probe |
| NBA | nba.com | sport | Signup availability |
| Playtomic | playtomic.io | sport | Login-error differential |
| Sporcle | sporcle.com | sport | Signup availability |
| Strava | strava.com | sport | Signup availability |
| Uniscore | uniscore.com | sport | Password-reset differential |
| Blablacar | blablacar.com | transport | Signup availability |
| Emirates | emirates.com | travel | Signup availability |
| Polarsteps | polarsteps.com | travel | Signup availability |
| Skyscanner | skyscanner.net | travel | Login-error differential |

## XenForo community forums (131)

All checked by the same **non-intrusive login-error differential** (a login attempt with a junk password returns "The requested user could not be found" for an unknown address vs "The password you entered is incorrect" for a real one — no email is sent). Also available through the optional stealth-browser tier for Cloudflare-fronted instances.

| | | |
|---|---|---|
| 4gameforum.com | 650f.bike | 8wayrun.com |
| animebase.me | antique-bottles.net | antiscam.space |
| bayoushooter.com | blast.hk | board.mddc.dev |
| bookandreader.com | caves.ru | chiase.org |
| discussfastpitch.com | dragonbyte-tech.com | dronepilots.community |
| dumpz.ws | erogen.club | f1-forum.fi |
| fanficslandia.com | fanforum.uscho.com | ffhl.kld.im |
| finforum.net | firesofheaven.org | foforum.fr |
| forobeta.com | foropl.com | foropuros.com |
| fortreeforums.xyz | forum-mechanika.pl | forum.alidropship.com |
| forum.amperka.ru | forum.bestflowers.ru | forum.beyond3d.com |
| forum.console-tribe.com | forum.coralvuehydros.com | forum.crocieristi.it |
| forum.elektrolab.eu | forum.evendim.ru | forum.facmedicine.com |
| forum.freeso.org | forum.igrarena.ru | forum.iinkor.com |
| forum.lottoced.com | forum.lvivport.com | forum.macplanete.com |
| forum.maidenfans.com | forum.mcmodding.ru | forum.mmajunkie.com |
| forum.mohaddis.com | forum.motorguia.net | forum.motorka.org |
| forum.neformat.com.ua | forum.questionablequesting.com | forum.rudtp.ru |
| forum.team-mediaportal.com | forum.vuurwerkcrew.nl | forum.wordreference.com |
| forum.xanasoft.com | forum.xlegio.ru | forumprawne.org |
| forumroman.com | forums.animeuknews.net | forums.arcade-museum.com |
| forums.canadiancontent.net | forums.immigration.com | forums.majorgeeks.com |
| forums.njpinebarrens.com | forums.sonicretro.org | forums.talkseafishing.co.uk |
| forums.techarp.com | forums.vintagefashionguild.org | forums.vitalfootball.co.uk |
| forums.wolflair.com | forumyuristov.ru | gamesfrm.com |
| gaminglatest.com | gulfcoastgunforum.com | icq.icqchat.co |
| ilvesfoorumi.com | immobilio.it | indiedev.gg |
| kellofoorumi.fi | khatmenbuwat.org | klocksnack.se |
| kontrolkalemi.com | mac-help.com | macosx.com |
| mb.srb2.org | mmo-dev.info | newdayrp.com |
| newf319.com | niflheim.top | not606.com |
| nucastle.co.uk | nullcave.club | nygunforum.com |
| office-forums.com | otland.net | ourdjtalk.com |
| outgress.com | oyunlabi.com | palungjit.org |
| parkrocker.net | phorum.armavir.ru | physicsforums.com |
| piratebuhta.club | pixelexit.com | predpriemach.com |
| reincarnationforum.com | rmmedia.ru | rollitup.org |
| rusfishing.ru | sadece1.com | salsaforums.com |
| sexforum.ws | skyblock.net | speedsolving.com |
| tech247.fi | texasguntalk.com | tgforum.ru |
| thebuddyforum.com | viethoagame.com | volkswagen.lviv.ua |
| vozer.net | w7forums.com | wasm.in |
| weblogistics.vn | windows10forums.com | worldofplayers.ru |
| xen-concept.com | xentr.net |  |

## Other community forums (25)

Checked by the same non-intrusive login-error differential (MyBB and similar forum software).

| | | |
|---|---|---|
| community.mybb.com | cracked.to | demonforums.net |
| discussion.cambridge-mt.com | drachenhort.user.stunet.tu-freiberg.de | forum.blitzortung.org |
| forum.codeigniter.com | forum.kodi.tv | forum.ndemiccreations.com |
| forums.nextpvr.com | forums.therian-guide.com | nattyornotforum.nattyornot.com |
| onlinesequencer.net | thecardboard.org | www.babeshows.co.uk |
| www.badeggsonline.com | www.bios-mods.com | www.biotechnologyforums.com |
| www.blackworldforum.com | www.bluegrassrivals.com | www.chinaphonearena.com |
| www.clashfarmer.com | www.cpaelites.com | www.cpahero.com |
| www.thevapingforum.com |  |  |
