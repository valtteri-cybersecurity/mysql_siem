# UFW-keräys ja valinnainen localhost-suodatus

Oletus säilyttää kaikki kelvolliset tapahtumat. Migraatio 026 ei aktivoi sääntöjä.
Ainoa tuettu sääntö on LOCALHOST_MYSQL_AUDIT_001, versio 1: AUDIT, TCP,
127.0.0.1 → 127.0.0.1:3306. Molempien IN/OUT-kenttien on oltava yksiselitteisesti
ilmoitettuja, vähintään yhden lo ja toisen tyhjä tai lo. Muut rajapinnat,
puuttuvat tai toistuvat kentät estävät suodatuksen. IPv6 ei kuulu sääntöön.
Virheelliset tapahtumat käsitellään edelleen karanteenissa.

Suodatus voi poistaa myös paikallisen hyökkääjän MySQL-yhteysyrityksen
raakamuotoisen todisteen. UFW ei todista yhteyden muodostanutta prosessia.
Myös paikallisten porttiskannausten näkyvyys voi heikentyä. Tilastot eivät
korvaa yksittäisiä raakaviestejä. Tätä sääntöä ei pidä tulkita vaarattoman
liikenteen tunnistukseksi.

## Käyttö

Käytä projektin virtuaaliympäristöä ja olemassa olevaa suojattua DB_*
asetusten lataustapaa. Älä anna tietokannan salasanaa komentoriviargumenttina.
Korvaa alla host- ja source-tunnisteet rekisterin oikeilla UFW-tunnisteilla.
Esikatselu ja tilastot ovat vain lukevia. Käyttöönotto ja poiskytkentä tarvitsevat
erillisen ylläpitäjän tietokantayhteyden; runtime-käyttäjälle ei myönnetä
suodatusasetusten tai auditointihistorian kirjoitusoikeuksia.

```bash
python -m config.ufw_filters preview --host-id 1 --source-id 2 --start 2026-10-28T00:00:00Z --end 2026-10-29T00:00:00Z
python -m config.ufw_filters enable --host-id 1 --source-id 2 --actor operator --reason 'Esikatselu ja näkyvyyden menetys hyväksytty' --acknowledge-local-evidence-loss
python -m config.ufw_filters statistics --host-id 1 --source-id 2 --start 2026-10-28T00:00:00Z --end 2026-10-29T00:00:00Z
python -m config.ufw_filters disable --host-id 1 --source-id 2 --actor operator --reason 'Palautetaan yksityiskohtainen keräys'
```

Esikatselussa complete=false tarkoittaa rajattua osatulosta, ei koko aikavälin
määrää. Esikatselu käyttää event_time-aikaa ja UTC-eristystä, ei created_at-aikaa.
Tulos ei ennusta tulevaa suorituskykyä. Tilastokomennon rajat ovat kokonaisia UTC-tunteja.

Jokainen hyväksytty asetusmuutos tallentaa määritelmän, version, käyttäjän,
syyn ja UTC-ajan auditointitauluun. Kerääjä tarkistaa asetuksen vastaavan viimeistä
auditointimerkintää. Virheellinen asetus keskeyttää keräyksen ilman lukuposition
etenemistä. Keräys ja asetusten muuttaminen käyttävät samaa MySQL-lukkoa.

Suodatetuista tapahtumista säilyy lähdekohtainen SHA-256-tunnistekirjanpito sekä
täsmälliset uniikkilaskurit UTC-tunneittain. Niitä ei saa poistaa, jos laskurien
idempotenssi halutaan säilyttää. Kirjanpito vie levytilaa; suodatus ei ole ilmainen
laskurioptimointi. Karanteeni, normaalit tapahtumat, tunnisteet, laskurit ja
checkpoint vahvistetaan samassa transaktiossa. Poiskytkentä ei palauta aiemmin
suodatettuja rivejä eikä poista tilastoja. Aiemmin raakadataksi tallennettuja
rivejä ei poisteta myöhemmin säännön vuoksi.

Analyysit laskevat tallennettua raakadataa. Niiden yhteenvedot ilmoittavat
intentionally_filtered_events-määrän erikseen, kun aikavälillä on poissulkemisia.
Traffic coverage_status pysyy UNKNOWN-arvossa. Kerääjän HEALTHY ei takaa koko
historian täydellisyyttä.

## Toistettava mittaus

`tests/identity/test_ufw_performance_mysql.py` käynnistää vain yksityisen,
verkottoman testipalvelimen. A käyttää ennen muutoksia talletettua lähdekoodia;
B optimointia ilman suodatusta; C optimointia suodatuksella. Jokainen tapaus
käyttää omaa tietokantaa, samoja synteettisiä rivejä ja samaa skeemaa.

```bash
SIEM_TEST_MYSQL=1 SIEM_UFW_BENCHMARK=1 SIEM_UFW_BASELINE_ROOT=/polku/phase3-lahdekoodiin SIEM_UFW_BENCHMARK_OUTPUT=/tmp/ufw-benchmark.json python -m pytest -s -q tests/identity/test_ufw_performance_mysql.py
```

Mittaus sisältää aktiivisen lokin, kiertolokin ja gzip-käsittelyn. Raportoitu
MySQL-tila on information_schema-taulujen data_length+index_length-arvio,
mukaan lukien pysyvä suodatustunnisteiden kirjanpito. Pythonin tracemalloc-huippu
kuvaa keräyksen allokaatioita; prosessin RSS-huippu sisältää myös testiaineiston
valmistelun. CPU-aika koskee Python-asiakasta, ei MySQL-palvelinta. Gzip-vaiheen
aika sisältää myös arkistorivien SQL-käsittelyn. Ajat ovat yhden koneen mittauksia,
eivät tuotantoympäristön lupauksia.
