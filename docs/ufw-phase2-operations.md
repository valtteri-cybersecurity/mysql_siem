# UFW-vaihe 2: keräys ja automaattisen päivityksen edellytykset

## Keräys ja karanteeni

Migraatio 024 lisää ufw_quarantine-, ufw_quarantine_origins-, ufw_archives- ja
ufw_archive_failures-taulut. Alkuperäistä historiaa ja checkpointteja ei nollata.
Karanteenin sisältö on arkaluonteista lokidataa, ei tavallista sovelluslokia.
Virheellisen rivin alkuperäiset tavut säilyvät, ja erillinen alkuperärivi erottaa
tiedostot ja niiden tavupositiot. Sisältö deduplikoidaan lähteen ja SHA-256:n mukaan.

Tavallinen tapahtuma, karanteeni ja niitä koskeva tiedostopositio vahvistetaan
samassa transaktiossa. MySQL- tai identiteettivirhe peruu erän. Kerääjän
poistumiskoodi on tällöin ei-nolla. Kiertolokin katoaminen kesken erän on myös tiedostovirhe: erää ei kuitata onnistuneeksi.
Vahvistettu karanteeni ei itsessään ole
järjestelmävirhe. Puuttuva portti on 0; eksplisiittinen 0 tai virheellinen arvo ei ole.
Aikaleimat tukevat muotoa YYYY-MM-DDTHH:MM:SS[.ffffff]Z tai ±HH:MM-aikavyöhykettä.
Tuntematonta -00:00-aikavyöhykettä ei hyväksytä.

## Gzip-arkkitehtuurin valinta

Gzip-virran purkutilaa ei voi turvallisesti säilyttää MySQLin tavupositiolukuna.
Jokaisella cron-kerralla alusta purkaminen olisi tehotonta. Siksi yksi erillinen,
rajattu palvelukäyttäjän purkuprosessi tekee yksityisen purkutiedoston kerran.
Se voi jatkaa toimintaansa kerääjän cron-prosessin päättymisen jälkeen.
Tapahtumia ei tallenneta keskeneräisestä tai CRC-varmentamattomasta purkutuloksesta.

- Muisti: 64 KiB lohkot, purkuprosessin osoiteavaruus enintään 512 MiB.
- Levy: yksi purkutulos enintään 512 MiB, välimuistille 1 GiB:n raja ja
  vapaan tilan 256 MiB:n varaus. Epäonnistunut osittainen purkutulos säilytetään.
- Pakattu tiedosto: enintään 64 MiB; purkusuhde enintään 200.
- Purkuprosessi: 120 sekunnin CPU- ja seinäkelloaikaraja, yksi prosessi kerrallaan.
- Jatkaminen: CRC-varmennetusta purkutiedostosta luetaan seuraavalla cron-kerralla
  suoraan loogisesta offsetista. Epäonnistunut tallennuserä ei siirrä offsetia.
- Purkuprosessin kaatuminen: yksi uudelleenkäynnistys sallitaan ennen pysyvää
  virhetilaa. Osittaista purkua ei tulkita valmiiksi.
- Identiteetti: arkiston SHA-256 ja lähdekohtainen checkpoint. Muuttumattoman
  tiedoston hash-välimuisti sidotaan myös inodeen, kokoon, mtimeen ja ctimeen.
- Eheys: kaikkien gzip-jäsenten CRC tarkistetaan; lähde varmennetaan ennen ja
  jälkeen purun. Linkkejä ei seurata. Hakemisto on 0700 ja tiedostot 0600.

Aktiiviset lokit saavat ensin 3/4 rivimäärä- ja aikabudjetista, jos arkistoja on.
Arkistot käyttävät jäljelle jäävän budjetin; yksi arkisto saa enintään 1000 riviä
vuorollaan. Arkistochunkin tapahtumat ja looginen offset vahvistetaan yhdessä.
Aktiivisen lokin aiempi commit säilyy, vaikka arkisto epäonnistuisi. Kokonaistila
on silloin FAILED ja poistumiskoodi ei-nolla. FAILED-arkistot eivät estä muiden
arkistojen etenemistä. Niitä ei kuitata automaattisesti käsitellyiksi.

CRC-varmennetun, suljetun arkiston viimeinen vajaa lokirivi säilytetään karanteenissa
INCOMPLETE_ARCHIVE_LINE-syyllä. Aktiivisen tiedoston vajaa rivi jää odottamaan
seuraavaa keräyskertaa. Valmiin arkiston purkutiedosto poistetaan vasta checkpointin
COMPLETE-commitin jälkeen. Alkuperäistä gzip-tiedostoa ei poisteta tai muuteta.

Välimuisti on /var/lib/mysql_siem/ufw-archives. Sitä ei saa tyhjentää kesken
keräyksen. Puuttuva tai muuttunut varmentamaton arkisto jää virhetilaan; säilytä
lähde, välimuisti ja tietokantatila selvitystä varten. Kerääjälle ei anneta root-
tai sudo-oikeuksia. Asennin tunnistaa käynnissä olevan purkuprosessin huoltotilassa.

## Automaattinen UPGRADE: nyt estetty

Käyttäjän päätöksen mukaan automaattinen versionvalinta pysyy estettynä, kunnes
allekirjoitus on käytössä. Komento

    sudo bash install.sh --role server --upgrade

keskeytyy nykyisessä toteutuksessa ilman latausta. Se ei pyydä SHA:ta eikä hae
main-haaraa varavaihtoehtona. Tämä ei vielä ole toimiva automaattinen päivitys.

Automaattisen UPGRADEn käyttöönotto edellyttää erillistä toteutusta ja julkaisuvalmistelua:

1. Julkaisijan suojaama yksityinen allekirjoitusavain ja ennalta luotettu julkinen
   avain. Julkisen avaimen jakelu ja sormenjälki on varmennettava erillistä kanavaa
   käyttäen; ladattua avainta ei saa hyväksyä ensimmäisellä käyttökerralla automaattisesti.
2. Allekirjoitettu vakaan kanavan julkaisutiedosto, jossa ovat vähintään versio,
   täsmällinen commit, kanava ja voimassaoloraja. Main-HEAD ei ole hyväksytty julkaisu.
3. Bootstrap, joka tarkistaa allekirjoituksen ennen ladatun koodin suorittamista,
   varmistaa commitin vastaavuuden ja estää vanhentuneen tai alemman version.
4. Suojattu asennetun julkaisun tila, avaimen hallittu vaihto ja turvallinen
   epäonnistuminen verkko-, allekirjoitus- ja rollback-virheissä.
5. Testit virheellisille ja tuntemattomille allekirjoituksille sekä koko päivitysketjulle.

Ennen tätä vain ylläpitäjän erikseen hyväksymä manuaalinen päivitys on mahdollinen:

    sudo bash install.sh --role server --upgrade --revision HYVAKSYTTY_40_MERKIN_SHA

Vanha bootstrap ei päivity itsestään ennen uuden koodin lataamista. Siksi vanha
asennus tarvitsee kerran hyväksytyn siirtymäcommitin tällä manuaalisella polulla.
Tässä tehtävässä ei julkaista sellaista committia eikä määritetä tekaistua SHA:ta.
Kun allekirjoitettu bootstrap myöhemmin on julkaistu ja varmennettu, jatkopäivitykset
voidaan ajaa suojatusta asennushakemistosta /usr/local/lib/mysql_siem samalla
ilman SHA:ta annetulla komennolla. Alkuperäisen projektihakemiston vanha install.sh
voi edelleen vaatia kertaluonteisen siirtymän.

Varmuuskopiointi, eristetty palautuskoe, identiteetit, staging, huoltotila, migraatiot
ja lopputarkistus säilyvät myös manuaalisella päivityspolulla. UPGRADE-virhettä ei
korjata RESETillä eikä poistamalla huoltotilan merkintää käsin.
