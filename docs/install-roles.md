# Asennusroolit

Käyttöjärjestelmä ei määrää roolia. Debian 13, Ubuntu ja Linux Mint käyttävät
samaa asenninta.

| Rooli | Nykyinen tila |
|---|---|
| `server` | Paikallinen MySQL, UFW-/SSH-/DNS-keruu, mittarit, analyysi ja detection. Asennus alustaa uuden tietokannan; vanhan kannan poistaminen vaatii `RESET`-vahvistuksen. |
| `collector` | Asennus keskeytyy ennen järjestelmämuutoksia. HTTPS-lähetystä ja rekisteröintipalvelua ei vielä ole. |

```bash
sudo bash install.sh --role server
```

Ilman argumentteja näytetään valikko. Tallennettu `config/role.env` säilytetään,
eikä ristiriitaista roolia vaihdeta automaattisesti. Sovelluskoodi asennetaan
`/usr/local/lib/mysql_siem`-hakemistoon ja Python-ympäristö `/opt/mysql_siem-venv`-
polkuun. Git-klooni ja sen paikalliset muutokset säilyvät.

Katso [asennus- ja reset-käytäntö](debian-install.md). Ajastukset luodaan vain
asentimen hallittuun cron-lohkoon; erillisiä kopioitavia cron-malleja ei tarvita.

Keskitetyn arkkitehtuurin sovittu lähtökohta on yhteinen koodipohja ja paikallinen
MySQL molemmissa rooleissa. Nykyiset kerääjät tarvitsevat MySQL:ää tapahtumien,
lukupositioiden, lukitusten ja hyväksyttyjen identiteettien käsittelyyn. DNS käyttää
sitä lisäksi lähteisiin, suodatukseen ja keruutilaan. Mittarit tallennetaan MySQL:ään;
turvallisuusmittarit myös lukevat UFW-tietoja. Tuleva Sender/Receiver ja lähetyspuskuri
toteutetaan erikseen. Tässä vaiheessa ei oteta Collector-asennusta käyttöön.
