# Keräinten integraation uusintakatselmointi 25.10.2026

Tarkastettu työpuu: `main`, pohjacommit
`5c88e11555073d6a233d8a1b8d44dea4652356d5` sekä paikalliset muutokset.
Mukana olivat myös työssä ennestään olleet Auditin esivaatimustarkistukset ja
UFW-päivityksen turvatarkistus. Niitä ei poistettu.

**Johtopäätös: Processes-, Services- ja Audit-ketjut on toteutettu, mutta niiden
yhteistä integraatiota ei vielä voi hyväksyä valmiiksi.** Auditin P1-kilpailutilanne
on nyt korjattu ja testattu. Processes-CPU:n mittausvirhe sekä asennuksen,
käyttöoikeuksien ja palautumisen testauspuutteet jäävät seuraaviin vaiheisiin.
Vaiheeseen 2 ei ole siirrytty; se edellyttää käyttäjän lupaa.

## Korjatut kohdat 4–6

4. Cron-testien Auditin aktivointi eristettiin `audit_installation`-funktion kautta.
   Tuotannon komento ja suoritusjärjestys säilyvät. Testit eivät enää käynnistä
   oikeaa `config.audit_setup activate` -komentoa. Erilliset testit tarkistavat
   valmistelun/aktivoinnin argumentit, polut välilyönteineen ja virhekoodien
   välittymisen. UFW-päivitystesti vastaa nykyistä UTC-esitarkistusta; uudet testit
   varmistavat epäselvän historian, keskeytyneen migraation talletettujen määrien
   ja virheellisen migraatiotilan pysäyttävän päivityksen.
5. MySQL-testien migraatiolistat ulotettiin versioon 020. Auditin lisäämä kahdeksas
   paikallinen lähde huomioitiin rekisteröinti- ja uudelleenasennustesteissä.
   Migraatioiden 018–020 keskeytys- ja jatkamistesti tarkistaa historian säilymisen;
   versiossa 020 myös ylläpitäjän muuttamat Audit-kohdeasetukset säilyvät.
6. Auditin pakettikuvaus päivitettiin vastaamaan toteutettua MySQL-integraatiota.
   README ja `docs/local-collectors.md` kuvaavat automaattiajon, kehittäjäesikatselun,
   säilyttävän päivityksen, ensimmäisen ajon kattavuuden, palautumisen rajat ja
   erillisellä koneella tehtävän asennustestin hyväksymisehdot.

## Katselmointihavainnot ja niiden tila

### P1: Auditin tarkistuspiste voi hyväksyä lukemisen aikana korvatut lokitavut — korjattu

**Tila: korjattu ja varmennettu P1-korjauskierroksella.**

Alkuperäinen havaintopaikka: `ingestion/audit/get.py`, `read_log_batch`,
rivit 417–429 ennen korjausta. Alla kuvataan alkuperäinen virhe.

Tapahtumat luetaan ensin ja jäsennetään muistista. Lopuksi tiedosto avataan
uudelleen ja tarkistuspisteen sormenjälki lasketaan sen **senhetkisistä** tavuista.
Jos sama inode tyhjennetään ja täytetään uudelleen vähintään vanhaan kokoon näiden
vaiheiden välissä, koon tarkistus ei havaitse muutosta. Vanha tapahtuma palautuu,
mutta tarkistuspiste hyväksyy uuden tiedostosisällön ja voi ohittaa sen pysyvästi.

Toistettu väliaikaisella synteettisellä lokilla: lukija luki tapahtuman 12;
jäsennysvaiheessa samaan inodeen kirjoitettiin samanpituinen tapahtuma 13.
Lukija palautti tapahtuman 12 ja EOF-tarkistuspisteen. Seuraava ajo palautti tyhjää,
vaikka tiedostossa oli tapahtuma 13. Virhettä ei syntynyt. Tämä koskee esimerkiksi
samanaikaista copytruncate/uudelleenkirjoitusta; tavallisen rename-rotaation
onnistuminen ei todista tämän tilanteen turvallisuutta.

Toteutettu korjaus: `log_position` laskee tarkistuspisteen sormenjäljen
lukemishetken tavuista. Lukeminen laskee lisäksi tiivisteen jokaisesta luetusta
tiedosto-osuudesta. `verify_log_reads` avaa samat inodet uudelleen ja vertaa
kaikki luetut osuudet ennen palautusta. Muuttunut sisältö pysäyttää erän.
MySQL-testit varmistavat vanhan tapahtumahistorian ja tarkistuspisteen säilymisen.
Tarkistus käyttää tavallisia funktioita, sanakirjoja, listaa ja silmukoita.
Se ei tallenna raakaa lokisisältöä eikä muuta version 2 tarkistuspistemuotoa.

### P2: Processes tallentaa CPU-mittaukseksi ensimmäisen näytteen nollan

Paikka: `metrics/processes/get.py`, rivit 10 ja 26–27.

Jokainen minuutin ajo aloittaa uudessa Python-prosessissa. Lisäksi psutilin
prosessivälimuisti tyhjennetään ennen havaintoa. `cpu_percent` luetaan siten
ensimmäisellä kutsulla ilman aiempaa vertailunäytettä, jolloin nolla ei kuvaa
mitattua CPU-käyttöä. Kontrollissa oma CPU:ta kuormittava prosessi tuotti keräimen
kautta `0.0`, mutta aiemman näytteen ottanut psutil-olio raportoi `99.3` prosenttia.

Korjaus: laske CPU-käyttö kahden CPU-aika-/aikanäytteen erotuksesta tai tallenna
puuttuva mittaus tuntemattomana. Lisää testi, joka ei hyväksy ensimmäisen näytteen
nollaa todelliseksi käyttömittaukseksi. Prosessin identiteetti ja muutosten
kirjaaminen eivät poista tätä havaintotiedon oikeellisuusongelmaa.

### P2: Auditin etuoikeutetun asennus- ja palautumisketjun testikattavuus on vajaa

Paikat: `config/audit_setup.py`, etenkin `install_audit` ja `main`;
`tests/audit/test_audit_launcher.py` ja `test_audit_installation.py`.

Manifestin kulku asentimelta käynnistimelle on testattu, mutta käyttöjärjestelmän
operaatiot on siinä korvattu testeissä. Erilliset regressiotestit puuttuvat muun
muassa ristiriitaisille aktiivisille säännöille, immutable-tilalle, konfiguraation
varmuuskopioinnille, osittain epäonnistuvalle oikeuksien valmistelulle ja
aktivoinnin virheessä palautettavalle maintenance-esteelle. Lisää näille
hallittuja virhetilannetestejä ennen asennusketjun hyväksyntää.

### P2: Varsinaista keräystä ei ole osoitettu asentimen runtime-tietokantaoikeuksilla

Paikat: `tests/identity/test_audit_mysql.py` ja `test_snapshot_mysql.py`.

Näiden oikeat MySQL-transaktiot käyttävät yksityisen testipalvelimen
pääkäyttäjäyhteyttä. Se osoittaa SQL:n, atomisuuden ja identiteettirajauksen
käyttäytymistä, mutta ei todista asentimen myöntämien vähimmäisoikeuksien
riittävyyttä. Lisää kolmen keräimen integraatiotesti asentimen oikeuksilla:
onnistuva keräys ja uusinta sekä kielletyt historian/rekisterin muutokset.

### P2: Konekohtainen asennuksen hyväksyntä puuttuu

Processes/Services käyttävät testeissä korvattuja Linux-havaintoja. Auditd:n
aktiivisia sääntöjä, atomisen korvauksen jälkeistä valvontaa, oikeaa rotaatiota,
uudelleenkäynnistystä, systemd:n rajoituksia ja työntekijän todellista
UID/GID/capability-tilaa ei ole tässä työssä hyväksyntätestattu.

Tämän suoritusympäristön muuttamaton `config.audit_setup check` palautti
`NOT READY`: `mysql_siem`-tili ja auditd-työkalut puuttuvat, auditd-palvelua ei
voitu varmistaa eikä auditd.conf ollut saatavilla. Esitarkistus ei tehnyt
järjestelmämuutoksia. Tulos kertoo testausympäristön puutteista, ei onnistuneesta
tai epäonnistuneesta täydestä asennuksesta.

Suorita `docs/local-collectors.md`-ohjeen tuore asennus, historian säilyttävä
päivitys, päivityksen uusinta ja vikatilanteista palautuminen erillisessä VM:ssä.
Asennin lataa virallisen `main`-commitin, joten paikalliset korjaukset on saatava
testattavaan julkaisuun ennen tavallisen asentimen käyttämistä tähän tarkoitukseen.

## Valmiusarvio

| Osa | Arvio |
| --- | --- |
| Processes | Identiteetti, migraatio 018, transaktiot ja cron toteutettu; CPU-mittauksen korjaus ja konekohtainen hyväksyntä puuttuvat |
| Services | Identiteetti, migraatio 019, transaktiot ja cron toteutettu; konekohtainen hyväksyntä puuttuu |
| Audit | P1-kilpailutilanne korjattu ja testattu; käyttöoikeuksien ja oikean asennuksen hyväksyntä puuttuu |
| Asennustestin valmistelu | Ohje ja testattavat hyväksymisehdot valmiina; tarvitaan erillinen sopiva VM ja korjaukset sisältävä julkaisu |
| Kokonaisintegraation hyväksyntä | Ei vielä valmis |

## Aiemman katselmointikierroksen testitulokset

- Tavallinen koko testisarja: **3848 läpäisty, 339 ohitettu**. MySQL-testit vaativat
  erillisen opt-in-ajon; ohituksia ei tulkita onnistuneiksi tietokantatesteiksi.
- Uudet asennusrajauksen ja UFW-esitarkistuksen kohdennetut testit: **30 läpäisty**.
- Koko projektin Ruff, `git diff --check` sekä `bash -n install.sh config/run_with_env.sh`:
  hyväksytty.
- Audit-lokin uudelleenkirjoituksen ja Processes-CPU:n erilliset kontrollit:
  yllä kuvatut ongelmat toistettiin. Ne eivät kuulu vielä korjattuina regressioina
  vihreään testisarjaan.
- Kohdennettu yksityisen MySQL:n ajo: **109 läpäisty, 4 rajattu pois**, kesto
  496,86 sekuntia. Mukana kaikki 18 Audit-tietokantatestiä, Processes/Services-
  transaktioketju, migraation 020 kaksi keskeytysskenaariota, paikallinen
  rekisteröinti, toistettu reset-asennus sekä migraatioista 015/017 jatkaminen
  versioon 020 asti. Ei epäonnistuneita testejä tässä kohdennetussa ajossa.
- Laaja MySQL-ajo keskeytettiin kohdennettua ajoa varten. Sitä ei lasketa
  onnistuneeksi kokonaisajoksi. Tuotannon tietokantaan tai järjestelmäpalveluihin
  ei tehty muutoksia.


Kohdennetun MySQL-ajon toistaminen projektin virtuaaliympäristössä:

```bash
SIEM_TEST_MYSQL=1 PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -p no:cacheprovider -v \
  tests/identity/test_audit_mysql.py \
  tests/identity/test_snapshot_mysql.py \
  tests/identity/test_local_identity_mysql.py \
  tests/identity/test_reset_installation_mysql.py \
  tests/identity/test_identity_mysql.py::test_running_migration_after_process_exit_can_resume \
  tests/identity/test_identity_mysql.py::test_017_running_after_process_exit_can_resume \
  -k 'not new_migrations_resume_without_changing_history or 020'
```

Rajaus sisältää uudet migraation 020 keskeytystestit. Neljä aiempien migraatioiden
018/019 keskeytysskenaariota on tästä ajosta rajattu pois; koko yksityisten
MySQL-testien sarjaa ei väitetä tämän rajatun ajon perusteella läpäistyksi.


## P1-korjauksen varmennus

- Ennen korjausta kuusi uutta kilpailutilanteen regressiotestiä epäonnistui:
  lukija hyväksyi muuttuneen lokin ilman virhettä. Korjauksen jälkeen samat testit
  läpäisevät ajon.
- Audit-yksikkötestit: **161 läpäisty**. Testit kattavat samanpituisen ja pidemmän
  uudelleenkirjoituksen, ensimmäisen ajon ja jatkoajon, muuttuneen rotaatiotiedoston
  sekä aiempien tavujen muutoksen viimeisen 256 tavun säilyessä ennallaan.
- Tavallinen lisäys, nimeämiseen perustuva rotaatio ja osittaisen erän turvallinen
  tarkistuspiste läpäisevät regressiotestit. Tarkistus lukee käsitellyt osuudet
  toisen kerran saman aikarajan sisällä; raakaa lokia ei säilytetä muistissa
  kokonaisena tarkistusta varten.
- Viimeisen tarkistuksen jälkeistä muutosta koskeva testi varmistaa, ettei uusi
  sisältö pääse korvaamaan alkuperäistä tarkistuspistesormenjälkeä: seuraava ajo
  pysähtyy muutokseen.
- Yksityinen MySQL: **20 läpäisty**. Uudet kaksi testiä varmistavat tapahtumien ja
  tarkistuspisteen säilymisen muuttumattomina virheessä sekä ensimmäisellä ajolla
  että jatkoajolla. Uusinta kerää korvaavan tapahtuman kerran ilman duplikaatteja.
- Koko tavallinen testisarja: **3859 läpäisty, 341 ohitettu**. Ohitetut
  MySQL-testit eivät ole tämän perusteella läpäistyjä; Auditin MySQL-testit
  suoritettiin erikseen yllä mainitusti.
- Koko projektin Ruff sekä `git diff --check`: hyväksytty.

Varmennuskomennot:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -p no:cacheprovider -q tests/audit
SIEM_TEST_MYSQL=1 PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -p no:cacheprovider -q tests/identity/test_audit_mysql.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -p no:cacheprovider -q
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m ruff check --no-cache .
git diff --check
```

Tämä kierros korjasi vain Auditin P1-virheen. Processes-CPU:n tai muiden P2-havaintojen
korjauksia ei aloitettu.
