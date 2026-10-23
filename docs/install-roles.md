# Asennusroolit

Rooli valitaan käyttötarkoituksen mukaan. Debian 13, Ubuntu ja Linux Mint voivat
käyttää samaa `server`-roolia; jakelu ei määrää koneen roolia.

| Rooli | Nykyinen tila |
|---|---|
| `server` | Nykyinen paikallinen SIEM-asennus: MySQL, paikalliset kerääjät, analyysi, tunnistus ja cron-ajot. Debian 13 / MySQL 8.4.13 vaativat vielä testauksen oikeassa kohdeympäristössä. Etätapahtumien vastaanottoa ei ole toteutettu. |
| `collector` | Valittavissa, mutta asennus keskeytyy virheeseen ennen mitään asennusmuutoksia. Toimivaa etäkeräystä ei vielä ole. |

## Käyttö

Ilman parametreja asennin näyttää Server/Collector-valikon ja edellyttää valintaa.
Automaattisessa ajossa rooli annetaan suoraan:

```bash
sudo bash install.sh --role server
sudo bash install.sh --role collector
```

Virheellinen tai puuttuva `--role`-arvo keskeyttää asennuksen. Ilman parametreja
suljettu syöte tai tyhjä valinta keskeyttää myös; oletusroolia ei valita.

Server jatkaa nykyistä asennusta paikallisine UFW-, SSH-, DNS- ja
metriikkakerääjineen. DNS on edelleen valinnainen AdGuard Home -integraatio.
Valmiiksi asennettu MySQL 8.0/8.4 säilytetään. Debianissa MySQL on asennettava
ennakkoon; Ubuntu/Mint voi asentaa nykyisen `mysql-server`-paketin tarvittaessa.
Migraatioiden tarkistus säilyy: asennin ei suorita `apply`-komentoa eikä muunna
vanhaa historiaa. Käyttöönoton ja lokien lukuoikeuksien ohje on
[Debian-asennusohjeessa](debian-install.md).

Server varmistaa yhteisellä `ensure_application_user`-toiminnolla `mysql_siem`-tilin
ennen riippuvuuksien asennusta ja omistajuuksien muuttamista. Puuttuva tili luodaan
järjestelmäkäyttäjänä omalla ryhmällä, lukitulla salasanalla, `/usr/sbin/nologin`-
shellillä ja `/var/lib/mysql_siem`-kotihakemistolla (750). Turvallinen olemassa
oleva tili käytetään uudelleen muuttamatta UID/GID-arvoja tai muita tilitietoja;
ristiriita keskeyttää asennuksen. Käyttäjä ei saa sudo-oikeuksia tai lisäryhmiä.

Collector keskeytyy jo ennen järjestelmä-, MySQL- ja käyttäjätarkistuksia.
Se ei asenna paketteja (myöskään PyMySQL:ää), luo käyttäjää tai MySQL-asetuksia,
muuta ajastuksia, käynnistä palveluita, suorita migraatioita tai avaa portteja.
HTTPS-osoitetta tai rekisteröintitunnusta ei vielä kysytä eikä tallenneta.
Kun Collector myöhemmin voidaan asentaa kokonaisena, se käyttää samaa yhteistä
käyttäjänhallintaa. Keskeneräistä asennusta varten käyttäjää ei nyt luoda.

## Nykyiset polut

Asennin käyttää projektin nykyistä sijaintia (`PROJECT_DIR`). `/opt/mysql_siem`
on sopiva sovelluskäyttäjän saavutettava paikka. Asetukset säilyvät projektin
`config/`-hakemistossa ja ajastusten lokit nykyisissä moduulihakemistoissa.
Salaisuustiedostojen nykyiset rajatut käyttöoikeudet säilyvät.
`/var/lib/mysql_siem` on järjestelmäkäyttäjän koti. Asennin ei siirrä vanhoja
asetuksia, lokeja tai tietoja automaattisesti.

Tuleva tavoite on sovellus `/opt/mysql_siem`, asetukset `/etc/mysql_siem`,
pysyvä tila `/var/lib/mysql_siem` ja mahdolliset omat tiedostolokit
`/var/log/mysql_siem`. Asetus- ja lokipolkujen siirto tarvitsee erillisen,
nykyiset asennukset huomioivan muutoksen.

## Kerääjien MySQL-riippuvuudet ja seuraava vaihe

| Osa | Nykyinen riippuvuus | Irrottamisen edellytys |
|---|---|---|
| UFW: `ingestion/ufw_to_mysql.py` | Tietokantayhteys, lähdeidentiteetti, lukitus, tiedoston lukukohta ja tapahtumien tallennus. | Hyödynnä nykyistä jäsennystä, erota tapahtumien muodostus SQL-tallennuksesta ja määritä paikallisen lukukohdan sekä toimituskuittauksen suhde. |
| SSH: `ingestion/auth/main.py`, `collector.py`, `db.py` | Tapahtumat ja lukukohdat tallennetaan MySQL:ään transaktiona; keruu käyttää tietokantalukkoa ja rekisteröityä identiteettiä. | Säilytä tietokannasta riippumaton `parser.py`; erota paikallinen keruu, identiteetti, lukitus ja lukukohtien tallennus tietokantakirjoittajasta. |
| DNS: `ingestion/dns/collector.py`, `db.py`, `main.py` | AdGuard-kyselyn lisäksi tietokantaan sidotut tilat, lähteet, suodatus, lukitus ja tallennus. | Hyödynnä nykyistä AdGuard-adapteria; päätä missä integraatio suoritetaan ja erota sen SQL-tila sekä tallennus ennen mahdollista etäajoa. |
| Järjestelmä- ja tiedostomittarit: `metrics/system`, `metrics/filesystem` | `get.py` lukee paikallisia tietoja, mutta käynnistys ja tallennus tarvitsevat MySQL:n. | Käytä nykyisiä mittausfunktioita ja erota DB-vapaa käynnistys sekä tulosten toimitus nykyisestä SQL-tallennuksesta. |
| Turvallisuusmittarit: `metrics/security/get_data.py` | Paikalliset havainnot ja MySQL:stä lasketut UFW-yhteenvedot ovat samassa kerroksessa. | Erota koneen omat mittaukset keskitetysti laskettavista yhteenvedoista; pelkkä tallentajan vaihto ei riitä. |
| Identiteetti ja käynnistys | `database/identity.py` hakee tunnisteet SQL:stä; `config/run_with_env.sh` lataa aina `mysql.env`-tiedoston. | Tuleva kerääjä tarvitsee palvelimen vahvistaman identiteetin ja DB-vapaan asetus-/käynnistyspolun. Hostname tai IP ei yksin ole luotettava identiteetti. |

`requirements-dns.txt` sisältää sekä Requests- että PyMySQL-riippuvuuden.
Sitä tai nykyistä serverin pakettilistaa ei voi käyttää sellaisenaan tulevan
Collector-asennuksen riippuvuuksina. Roolille tarvitaan oma vähimmäislista vasta,
kun DB-vapaa keruupolku on toteutettu. Tässä vaiheessa kerääjien koodia ja
riippuvuustiedostoja ei muuteta.

Seuraavan vaiheen edellytykset:

1. Sovi tapahtumamuoto ja palvelimen vahvistaman kone-/lähdeidentiteetin käyttö.
   Erota nykyinen keruu ja jäsennys SQL-tallennuksesta pienin, testatuin askelin.
2. Määritä paikallinen tila, lukitukset, toimituskuittaukset, uudelleenyritykset ja
   kaksoistapahtumien käsittely. Nykyinen tapahtumien ja lukukohdan yhteinen
   tietokantatransaktio ei siirry sellaisenaan etätoimitukseen.
3. Toteuta ja testaa erikseen HTTPS-vastaanotto, rekisteröinti ja lähetysjono.
   Asennus pyytää HTTPS-osoitteen ja kertakäyttöisen tunnuksen piilotetulla
   syötteellä. Tunnusta ei anneta komentorivillä eikä tulosteta lokeihin.
   TLS-varmennuksen pitää tarkistaa luottamusketju ja palvelimen nimi ilman
   varmennuksen ohitusta. Rekisteröinnin pitää antaa kerääjälle oma identiteetti
   ja myöhemmän liikenteen tunniste, jonka voi peruuttaa.
4. Ota Collector-asennus käyttöön vasta, kun sillä on DB-vapaat riippuvuudet,
   rajatut lukuoikeudet, yhteinen järjestelmäkäyttäjän tarkistus ja kokonaisuutena
   testattu toimituspolku. Etäkone ei saa MySQL-tunnuksia tai suoraa DB-yhteyttä.

Tässä muutoksessa ei toteuteta etäkeräystä, API:a, rekisteröintiprotokollaa tai
lähetysjonoa eikä kirjoiteta nykyisiä kerääjiä uudelleen.
