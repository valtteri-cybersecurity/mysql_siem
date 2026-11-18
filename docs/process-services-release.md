# Process & Services Collector 2.0

## Rakenne ja tiedot

Asennettu palvelin ajaa molemmat kerääjät cronista minuutin välein palvelutilillä. `config/run_with_env.sh` lataa tietokanta-asetukset ja paikalliset identiteetit sekä osallistuu asennuksen ylläpitolukitukseen. Kumpikin kerääjä ottaa tietokannan, kerääjätyypin ja isännän mukaan rajatun lukon. Nykytila, tapahtumat, tarkistuspiste, mittausikkuna ja onnistunut Collector Health -päivitys vahvistetaan yhdessä MySQL-transaktiossa.

- Process tunnistaa instanssin boot ID:n, PID:n ja käynnistysajan perusteella isännän ja lähteen kontekstissa. Boot ID tallennetaan tarkistuspisteeseen. Vaihtunut tai aiemmin tuntematon boot ID muodostaa uuden lähtötilan. PPID ja varmennettu vanhempiprosessin avain tallennetaan eri kenttiin. UID, EUID, GID ja EGID kuvaavat havaittuja oikeuksia. Suoritettavan tiedoston varmennettu identiteetti perustuu procfs:n kautta luettuun tiedostometadataan.
- Services tunnistaa systemd-yksiköt nimellä ja käyttää kanonista `Id`-kenttää aliasnimien yhteisissä tilahavainnoissa. `MainPID` ja konfiguroitu `User` kuvaavat eri asioita. Restart-laskuria ei johdeta MainPID-arvosta. `systemctl` saa rajatun ympäristön ja kiinteän ominaisuuslistan.
- `process_state` ja `service_state` sisältävät viimeisimmän hyväksytyn tilan. Delta lisää, päivittää tai poistaa tarpeelliset rivit. CPU- ja RAM-arvojen muutos voi päivittää nykytilaa ilman tapahtumaa. Tapahtumiin tallentuvat hyväksyttyjen tilannekuvien erot tauluihin `process_events` ja `service_events`.
- `process_measurement_windows` ja `service_measurement_windows` käyttävät viiden minuutin UTC-ikkunoita ja hyväksyttyjen havaintojen laskureita. Palvelukohtaiset tiedot alkavat tapahtuma- tai vikatilahavainnosta. Prosessikohtainen kooste sisältää rajatut ohjelma- ja suhdetiedot. Koosteen havaintomäärät kuvaavat otantaa.
- `collector_snapshots` kertoo viimeisimmän hyväksytyn tilannekuvan. `collector_health` kertoo viimeisimmän tunnetun yrityksen tuloksen ja rajatun siirtymähistorian. Tietokantakatkon aikana tieto voi jäädä paikalliseen kerääjälokiin. Epävarmassa commitissa tarkistuspiste ja ikkunan viimeisin aikaleima määräävät, onko alkuperäinen havainto jo vahvistettu.

Processin tarkistus hylkää kesken identiteetin varmennuksen vaihtuneen PID:n havainnon. Services käsittelee systemd:n lainatut, kenoviivan sisältävät aliasnimet, hylkää kesken jääneen ominaisuusrivin ja tarkistaa myös inventaarion aikana kadonneet ladatut yksiköt. Tavallinen systemd:n ominaisuuskyselyn aiheuttama tiedostopohjaisen yksikön latautuminen on sallittu.

## Tietosuoja ja ylläpito

Prosessikeräys rajaa luettavat kentät identiteettiin, oikeuksiin, suoritettavan ohjelman metadataan ja mittareihin. Palvelukeräys käyttää rajattua ominaisuuslistaa. Varmennetut vanhempiavaimet, tiedostopolut, nimet ja oikeustiedot voivat yksilöidä käyttäjiä tai työkuormia. Rajoita pääsyä nykytilaan, tapahtumiin ja varmuuskopioihin. Tietokantavirheistä tallennetaan tai tulostetaan rajattu luokka.

Oletusbudjetti on 40 sekuntia inventaariolle, 65 536 prosessia ja 4 096 palveluyksikköä. Yhden systemctl-kutsun oletuskatto on 5 sekuntia ja 8 MiB tulostetta. Kattoja voi pienentää `SIEM_SNAPSHOT_*`-asetuksilla. Kirjoitusrajan ylitys peruu koko tilannekuvatransaktion. Koosteen yksityiskohtien rajaus raportoidaan laskureilla.

Retention esikatselee tapahtumia 180 päivän ikärajalla. Koosteiden, yksityiskohtien ja Health-siirtymien oletusraja on 30 päivää. Esikatselun komento projektihakemistossa, tietokanta-asetusten lataamisen jälkeen

```bash
python -m metrics.snapshot_retention --kind services --host-id 1 --source-id 2
```

Käytä oikeita rekisteritunnisteita. Ylläpitäjän rajattu kirjoitusajo vaatii `SIEM_SNAPSHOT_RETENTION_ENABLED=1` ja `--apply`. Tapahtumahistorian aikaraja on esikatselua varten. Vanhin vanhempiprosessin identiteettitieto voi sijaita aiemmassa tapahtumassa. Uusin ikkuna, aktiivinen nykytila ja tekniset tarkistuspisteet suojataan.

## Asennus, päivitys ja manuaalinen matriisi

Migraatiot 040–043 tuovat boot ID:n, Healthin ja mittausikkunat. Palvelinpäivityksessä käytetään projektin tavallista `--upgrade`-polkua ja asennuksen omaa aiempaa paikallista tilaa. Varaa ennen päivitystä testikoneelle palautettava varmuuskopio. Tarkista päivityksessä vanhojen tilojen, tapahtumamäärien ja tarkistuspisteiden säilyminen sekä kahden peräkkäisen keräyksen Health ja ikkunat.

| Jakelu | Varmennus ja jatkotesti |
| --- | --- |
| Linux Mint 22.3 | Aidot lukuhavainnot UID 1000:lla, systemd 255. SQL-testit eristetyssä MySQL 8.0.46:ssa. |
| Ubuntu 24.04 LTS | Suorita aidot lukuhavainnot sekä palvelintilin koe olemassa olevan asennuksen kopiolla. Tarkista erityisesti listausmuoto, aliasnimet ja DropInPaths. |
| Debian 13 | Projektin asennuslogiikan mock-testit kuuluvat testisarjaan. Aja tuloste- ja päivitysmatriisi aidolla Debian 13:lla ja valmiiksi saatavilla olevalla MySQL:llä. |
| Rocky Linux 10 | Kokeile kerääjien lukuhavaintoja ja eristettyä MySQL-polkuja käsin. Nykyisen installerin jakelurajaus estää Rocky-asennuksen. |
| Fedora | Valitse ylläpidetty julkaisu ja kirjaa sen tarkka versio. Toista Rocky-rivin käsin tehtävät tarkistukset. Nykyisen installerin jakelurajaus estää Fedora-asennuksen. |

Kirjaa jokaiselta koneelta `/etc/os-release`, systemd-, Python-, psutil- ja MySQL-versiot sekä ajon UID ja ajastustapa. Aja lukuhavaintotesti tavallisena kerääjän käyttäjänä. Testaa oikeuspuutteet, tilamuutokset ja uudelleenkäynnistys vain erillisessä testikoneessa tai mockeilla. Yleinen kerääjän lukuyhteensopivuus ja installerin jakelutuki hyväksytään erikseen.

## Toistettavat testit

```bash
umask 022
python -m pytest -q -p no:cacheprovider
SIEM_TEST_SNAPSHOT_LIVE=1 python -m pytest -q -s tests/metrics/test_snapshot_release_live.py
SIEM_TEST_MYSQL=1 python -m pytest -q -s tests/identity/test_snapshot_mysql.py tests/identity/test_collector_runtime_mysql.py
SIEM_TEST_MYSQL=1 SIEM_TEST_SNAPSHOT_BENCHMARK=1 python -m pytest -q -s tests/identity/test_snapshot_mysql.py -k release_snapshot_workload
```

MySQL-fixture käyttää uutta tilapäistä datadiria ja Unix-socketia ilman verkkokuuntelua. Vikatestit kattavat myös simuloidut lukitus- ja deadlock-virhekoodit sekä oikean testiyhteyden katkaisun ennen committia. Kerääjien mittausikkunat ja nykytila tarkistetaan epäonnistumisen jälkeen.

Kuormavertailu käyttää Git-commitin `71f2d7be5acaf8b06618523b541758f02831966b` tallenninta ja nykyistä tallenninta samoilla synteettisillä havaintoriveillä. Kumpikin alustetaan kerran, sitten mitataan kolme ajoa. Kirjoituslaskurit mittaavat SQL-lauseita, tilarivilaskurit MySQL:n ilmoittamia kohderivejä. Upsert näkyy INSERT-lauseena. Aika sisältää testin synteettisen keräys- ja MySQL-polun, ja RSS kuvaa samaa testin Python-prosessia. JSON-tavumäärä mittaa hyötykuormaa. InnoDB:n sivut, indeksit, redo ja binlog ovat eri mittareita.


## Vertailumittaus

Alla ovat SQL-eräkirjoituksen vertailuajon mediaanit kolmesta toistosta. Arvot ovat vanha → uusi. Mittaus tehtiin ennen ensikäynnistysten transaktioeristyksen korjausta. Synteettinen aineisto sisältää samat rikastetut kentät kummallekin tallentimelle. Eristetty MySQL käytti 32 MiB:n InnoDB-puskuria. Lyhyiden ajojen seinäkellotuloksiin vaikuttivat samanaikaiset testit.

| Kerääjä ja otos | INSERT/UPDATE/DELETE-lauseet | Nykytilan kirjoitetut rivit | Kokonaisaika ms, min–max suluissa | SQL-aika ms | CPU ms | Huippu-RSS MiB |
| --- | --- | --- | --- | --- | --- | --- |
| Process, muuttumaton | 2/0/1 → 3/0/0 | 500 → 0 | 225 (217–252) → 215 (179–246) | 129 → 107 | 32 → 24 | 76.3 → 76.4 |
| Process, tavallinen | 3/0/1 → 5/2/1 | 500 → 254 | 222 (215–352) → 295 (257–326) | 157 → 210 | 36 → 42 | 76.4 → 76.4 |
| Process, suuri | 3/0/1 → 5/8/1 | 2000 → 1025 | 483 (411–1291) → 496 (478–671) | 357 → 360 | 70 → 117 | 76.4 → 76.4 |
| Process, kuorma | 4/0/1 → 5/39/1 | 10000 → 5125 | 2565 (2172–2795) → 2026 (1943–2560) | 2117 → 1609 | 404 → 562 | 79.9 → 80.4 |
| Services, muuttumaton | 2/0/1 → 3/0/0 | 200 → 0 | 167 (161–220) → 248 (142–304) | 113 → 194 | 18 → 20 | 80.4 → 80.4 |
| Services, tavallinen | 3/0/1 → 4/1/0 | 200 → 5 | 171 (158–200) → 183 (182–217) | 118 → 149 | 18 → 21 | 80.4 → 80.4 |
| Services, suuri | 3/0/1 → 4/1/0 | 600 → 15 | 175 (166–206) → 192 (154–396) | 130 → 133 | 28 → 30 | 80.4 → 80.4 |
| Services, kuorma | 3/0/1 → 4/1/0 | 2000 → 50 | 763 (426–823) → 261 (256–284) | 535 → 197 | 114 → 54 | 80.4 → 80.4 |

Jokainen mitattu ajo teki yhden commitin. Uusi Process päivittää edelleen muuttuneet CPU- ja RAM-arvot aktiiviseen nykytilaan. Vähennys koskee tilarivejä ja aiempia rivikohtaisia SQL-kutsuja. Suuren Process-otoksen rivikohtaiset 975 UPDATE-kutsua supistuivat kahdeksaan eräpäivitykseen. Uuden mallin SQL-lauseita voi silti olla enemmän kuin vanhan koko tilan uudelleenkirjoittavassa mallissa.

| Kerääjä ja otos | Nykytilan JSON, tavua | Tapahtumien JSON, tavua | Uusi ikkuna, tavua | Uusi Health-JSON, tavua |
| --- | ---: | ---: | ---: | ---: |
| Process, muuttumaton | 73710 → 73710 | 0 → 0 | 23550 | 92 |
| Process, tavallinen | 73710 → 73710 | 7056 → 7056 | 23550 | 92 |
| Process, suuri | 294860 → 294860 | 44190 → 44190 | 23550 | 92 |
| Process, kuorma | 1474330 → 1474330 | 221130 → 221130 | 23550 | 92 |
| Services, muuttumaton | 37070 → 37070 | 0 → 0 | 2858 | 92 |
| Services, tavallinen | 37065 → 37065 | 11025 → 11025 | 3803 | 92 |
| Services, suuri | 111855 → 111855 | 33165 → 33165 | 5698 | 92 |
| Services, kuorma | 373620 → 373620 | 110970 → 110970 | 12348 | 92 |
