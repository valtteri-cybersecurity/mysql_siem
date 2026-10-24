# Debian 13: Server-asennus

Asennin tukee Debian 13:a, Ubuntu 24.04 LTS:ää ja Linux Mintiä yhteisellä
asennuspolulla. Uusi reset-asennus on testattava erikseen oikeissa kohde-VM:issä;
yksikkötestit eivät todista koko Debian-asennuksen onnistumista.

## Edellytykset ja käynnistys

Debian 13:ssa tarvitaan valmiiksi Oracle MySQL 8.0/8.4 ja sen asiakasohjelma.
MariaDB ei ole tuettu. Ubuntu/Mint voi asentaa MySQL-palvelimen tarvittaessa.
Olemassa olevan palvelimen on vastattava paikallisessa socketissa
`/run/mysqld/mysqld.sock` root-hallintayhteydellä. Git ja verkkoyhteys GitHubiin
ovat tarpeen. Asennin käyttää aina virallisen repositorion uusinta `main`-versiota,
ei paikallisia kehitysmuutoksia.

```bash
git clone https://github.com/valtteri-cybersecurity/mysql_siem.git
cd mysql_siem
sudo bash install.sh --role server
```

**Tämä on kehitysvaiheen reset-asennus.** Olemassa oleva `mysql_siem`-tietokanta
poistetaan vain kirjoittamalla vahvistukseen täsmälleen `RESET`. Kaikki sen
historia, mittarit, hälytykset, rekisterit ja tietokantaan tallennetut asetukset
menetetään. Tallenna haluamasi tiedot erikseen ennen asennusta. Ilman hyväksyntää
asennin keskeyttää ennen asennetun palvelun muuttamista. Muita tietokantoja ei
nollata. Jaetun `pythonuser`-tilin muiden tietokantojen oikeudet estävät resetin.

Vanhaa skeemaa tai historiaa ei siirretä. Nykyinen migraatiomoottori alustaa uuden
tyhjän tietokannan kokonaan. Erillisiä käsin ajettavia migraatiokomentoja ei tarvita.
Paikalliset laite- ja lähdetunnisteet rekisteröidään automaattisesti uudelleen.

## Ohjelma, asetukset ja ajastukset

- Suojattu ohjelmakopio: `/usr/local/lib/mysql_siem`.
- Python: `/opt/mysql_siem-venv/bin/python`, riippuvuudet `requirements-dns.txt`:stä.
- Konekohtaiset asetukset: `/usr/local/lib/mysql_siem/config/*.env`.
- Asennetun version tunniste: `/usr/local/lib/mysql_siem/config/installed-version`.
- Käyttöönottotila ja ylläpitolukitus: `/usr/local/lib/.mysql_siem-local`.

Asennus onnistuu myös yksityisestä kotihakemistosta. Git-kloonia ei siirretä eikä
muokata. Järjestelmä-Pythonin paketteja ei asenneta pipillä. Palvelukäyttäjä on
`mysql_siem`, ilman sudo-oikeuksia. Tarvittavaa lokipääsyä varten asennin varmistaa
`adm`-jäsenyyden; muita lisäryhmiä ei hyväksytä.

Tunnistetut vanhat käyttäjäkohtaiset mysql_siem-cron-ajot poistetaan ja sovelluksen
systemd-ajot pysäytetään. Muut ajot säilytetään. Jos `/etc/crontab` tai `/etc/cron.d`
sisältää vanhan mysql_siem-ajon, asennin pyytää poistamaan sen ennen resettiä.
Edelleen käynnissä oleva vanha kerääjä estää resetin. Uudet ajastukset julkaistaan
vasta onnistuneiden tietokanta-, identiteetti- ja ohjelmistotarkistusten jälkeen.

## Keruun edellytykset ja virhetilanteet

UFW tarvitsee lokituksen ja luettavan `/var/log/ufw.log`-tiedoston. SSH tarvitsee
`/var/log/auth.log`-tiedoston tai `config/ssh.env`:ssä asetetun polun. Debian voi
käyttää pelkkää journaldia: tiedostolokitus ja aikavyöhykkeelliset ISO-aikaleimat
on silloin järjestettävä erikseen. Asennin ei kytke palomuuria päälle tai muuta
SSH-palvelimen asetuksia. DNS on valinnainen AdGuard Home -integraatio.

Jos asennus epäonnistuu resetin jälkeen, tietokantahistoriaa ei palauteta.
Keruu jää ylläpitotilaan. Korjaa ilmoitettu syy ja aja sama asennuskomento uudelleen;
olemassa olevan keskeneräisen kannan uusi reset vaatii jälleen `RESET`-vahvistuksen.
Älä poista ylläpitomerkintää tai käynnistä vanhoja kerääjiä käsin. Säilytettyjä
asetuksia käytetään uudelleen, mutta ohjelmakoodi ladataan uudestaan GitHubista.
