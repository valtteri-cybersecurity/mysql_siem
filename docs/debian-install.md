# Debian 13 -asennus: SIEM-CENTER

Tavoite on nykyisen ohjelman paikallinen keruu Debian 13:ssa. Palvelimella on
valmiiksi Oracle MySQL 8.4.13. Tätä asennusta tai MySQL 8.4:ää ei ole ajettu
kehitysympäristön testeissä; ne varmennetaan erikseen SIEM-CENTERissä.

## 1. Esitarkistus

Suorita komennot Debian-palvelimella tavallisena ylläpitokäyttäjänä
projektin juuresta. Tarkista ensin kohde, ota tietokannan ja asetusten varmuuskopiot
ja pysäytä mahdolliset tämän projektin vanhat cron-ajot ja muut prosessit.

```bash
cat /etc/os-release
/usr/sbin/mysqld --version
systemctl status mysql --no-pager
sudo /usr/bin/mysql --protocol=socket -u root -e "SELECT VERSION(), @@socket, @@version_comment;"
```

Edellytykset: `ID=debian`, pääversio 13, MySQL 8.4.13 ja `/usr/bin/mysql`,
paikallinen socket `/run/mysqld/mysqld.sock`. Nykyinen asennin ja ylläpitotyökalut
edellyttävät root-yhteyttä ilman salasanakyselyä tämän socketin kautta. Jos
esitarkistus vaatii salasanan tai epäonnistuu, selvitä ylläpitäjän kanssa nykyisen
asennusmenettelyn vaatima paikallinen tunnistautuminen ennen jatkamista.
Älä muuta MySQL-tunnistautumista tai palvelinta tämän ohjeen perusteella automaattisesti.

Asennin tunnistaa Debian 13:n `/etc/os-release`-tiedostosta ja edellyttää
valmista MySQL 8.0- tai 8.4-palvelinta. Se ei pyydä MySQL-palvelinpakettia,
jos palvelin on jo asennettu, eikä korvaa MariaDB:tä. Debianin
[default-mysql-server](https://packages.debian.org/trixie/default-mysql-server)
on MariaDB-pohjainen eikä sovellu Oracle MySQL:n korvikkeeksi tässä projektissa.
Ubuntu ja Linux Mint säilyttävät nykyisen `mysql-server`-asennuksen, jos palvelinta
ei vielä ole. Valmis MySQL säilytetään myös niissä.

Riippuvuudet asennetaan jakelun paketeista järjestelmän `/usr/bin/python3`:lle:
`python3-pymysql`, `python3-requests`, `python3-cryptography`, rsyslog ja cron
sekä nykyiset perustyökalut. Cryptography tarvitaan PyMySQL:n RSA-pohjaiseen
[caching_sha2_password-tunnistautumiseen](https://pymysql.readthedocs.io/en/latest/user/installation.html).
Älä asenna riippuvuuksia järjestelmä-Pythoniin pipillä. Asennin ei lisää
pakettivarastoja eikä muuta MySQL:n asetuksia tai käynnistä sitä uudelleen;
nykyinen `systemctl enable --now mysql` säilyy.

## 2. Asennus ja erillinen migraatio

Valitse tässä käyttötarkoituksessa `server`, joka kerää myös koneen omat lokit.
Rooli ei määräydy jakelusta. Ilman parametreja asennin näyttää roolivalikon.
`collector` keskeytyy toistaiseksi ennen asennusmuutoksia; katso
[roolien tila ja kerääjien MySQL-riippuvuudet](install-roles.md).

Sama käyttäjänhallinta koskee Debiania, Ubuntua ja Linux Mintiä riippumatta
koneen käyttötarkoituksesta. Asennin varmistaa Linux-käyttäjän `mysql_siem` ja
samannimisen ensisijaisen ryhmän ennen riippuvuuksia ja sovelluksen omistajuuksia.
Puuttuva käyttäjä luodaan `useradd --system` -komennolla, lukitulla salasanalla,
`/usr/sbin/nologin`-shellillä ja kotipolulla `/var/lib/mysql_siem`. Puuttuva koti
luodaan `install -d -m 750 -o mysql_siem -g mysql_siem` -komennolla.

Olemassa olevan tilin UID:tä, GID:tä, kotipolkua, shelliä tai salasanaa ei muuteta.
Ristiriitainen tili, jaettu UID/ryhmä, lisäryhmät, sudo-oikeudet tai turvaton
kotihakemisto pysäyttävät asennuksen ylläpitäjän tarkistettavaksi. Tarkistus käyttää
salasanan tilaa, ei tulosta salasanaa tai tiivistettä. Tyhjä turvallinen olemassa
oleva ryhmä voidaan käyttää uudelleen. Epäonnistuneen luonnin jälkeen mahdollinen
luotu ryhmä jätetään tarkistettavaksi; sitä ei poisteta automaattisesti.

Sovelluksen omistajuudet ja nykyiset cron-ajot kohdistuvat `mysql_siem`-käyttäjään,
eivät asennuksen käynnistäjään tai rootiin. Käytä käyttäjän saavutettavaa
projektipolkua, esimerkiksi `/opt/mysql_siem`; yksityinen kotihakemisto ei yleensä
sovellu. Poista vanhat tämän sovelluksen ajot aiemman käyttäjän crontabista
hallittuna ylläpitotoimena: asennin ei muokkaa muiden käyttäjien crontabeja.
MySQL:n `pythonuser`-tietokantakäyttäjän käsittely säilyy entisenä.


```bash
sudo bash install.sh --role server
```

Tuoreessa asennuksessa ensimmäinen ajo asentaa riippuvuudet ja luo puuttuvan
`config/mysql.env`-tiedoston, tietokannan ja perusskeeman. Se pysähtyy puuttuviin
migraatioihin **ennen projektin cron-ajojen luontia**. Tämä keskeytys on odotettu;
muiden virheiden kohdalla selvitä syy ennen jatkamista. Olemassa olevat asetukset
ja salasanat säilytetään. Älä kopioi kehityskoneen salasanoja palvelimelle.

Vain varmennetussa kohteessa ja ylläpitokatkon aikana suorita migraatiot erikseen:

```bash
sudo bash config/run_with_env.sh /usr/bin/python3 -m database.migrate status --admin-socket /run/mysqld/mysqld.sock
sudo bash config/run_with_env.sh /usr/bin/python3 -m database.migrate apply --admin-socket /run/mysqld/mysqld.sock
sudo bash config/run_with_env.sh /usr/bin/python3 -m database.migrate check --admin-socket /run/mysqld/mysqld.sock
sudo bash install.sh --role server
```

Asennin suorittaa edelleen vain migraatioiden `check`-komennon. Se ei suorita
`apply`-komentoa. Älä muokkaa migraatioita 013–017 tai niiden tarkistetiedostoja.
017 muuttaa `event_time`-sarakkeen tarkkuudeksi DATETIME(6); se ei muunna vanhaa
paikallisaikaista historiaa UTC-ajaksi. Epävarmaa UFW-historiaa, yhteenvetoja tai
hälytys-/tunnistustilaa sisältävää kantaa ei hyväksytä aktiiviseksi UTC-kannaksi.
Pidä sellainen kanta erillisenä historiakantana; älä tyhjennä sitä tai ohita
migraatiokirjanpitoa. SIEM-CENTERin tuore asennus aloitetaan tyhjällä kannalla.

## 3. Paikallisten kerääjien edellytykset

| Keräin | Debianissa tarkistettava |
|---|---|
| Järjestelmämittarit | `/proc/uptime`, `/proc/stat`, `/proc/loadavg`, `/proc/meminfo` ja juurilevyn tila. VM:n lämpötila-anturin puuttuminen tuottaa `None`-arvon. |
| Tiedostomittarit | GNU find ja sovelluskäyttäjän oikeudet `/etc`- ja `/home`-hakemistoihin. Laskenta kattaa käyttäjälle näkyvät tiedostot. |
| UFW | UFW-lokitus, `/var/log/ufw.log` ja ISO-aikaleima aikavyöhykkeellä. Asennin ei asenna tai kytke palomuuria päälle. |
| SSH | rsyslogin `/var/log/auth.log` tai `config/ssh.env`-tiedoston `SSH_AUTH_LOGFILE`, aikavyöhykkeellinen ISO-aikaleima ja lukuoikeus. Puuttuva lähde antaa SSH-ajossa `SKIPPED`, mikä ei todista toimivaa keruuta. |
| Turvallisuusmittarit | Paikallinen `/var/log/auth.log` ja paikalliset UFW-tapahtumat tietokannassa. Tarkista auth.log erikseen myös mukautettua SSH-polkuasetusta käytettäessä. |
| DNS (valinnainen) | Nykyinen AdGuard Home HTTPS -integraatio, erilliset tunnukset, CA-luottamus ja hyväksytty lähde. |

[OpenSSH 9.8](https://www.openssh.org/txt/release-9.8) ja
[10.0](https://www.openssh.org/txt/release-10.0) käyttävät myös nimiä `sshd-session`
ja `sshd-auth`. Jäsennin hyväksyy ne ja säilyttää nykyisen `service=sshd`-mallin,
joten brute-force-sääntöä tai tietokantaa ei muuteta.

```bash
sudo /usr/sbin/rsyslogd -N1
sudo stat -c '%a %U:%G %n' /var/log/auth.log /var/log/ufw.log
sudo -u mysql_siem test -r /var/log/auth.log
sudo -u mysql_siem test -r /var/log/ufw.log
```

Debian voi käyttää journaldia ilman näitä tiedostoja. Tässä vaiheessa kerätään
edelleen tiedostoista: ylläpitäjä varmistaa rsyslogin paikalliset reititykset.
Tarkista lokirivien aikaleimat paikallisesti näyttämättä arkaluonteisia lokitietoja
muille. Esimerkiksi `2026-10-23T12:34:56.123456+03:00` käy; vuodeton
`Oct 23 12:34:56` ei käy. Käytä tarvittaessa olemassa olevassa tiedostoon
kirjoittavassa rsyslog-säännössä
[RSYSLOG_FileFormat](https://docs.rsyslog.com/doc/reference/templates/templates-reserved-names.html)
-muotoa. Älä lisää toista sääntöä kirjoittamaan samoja tapahtumia samaan tiedostoon.
Validoi muutokset `rsyslogd -N1`-komennolla ennen niiden käyttöönottoa.
Vanhat vääränmuotoiset lokit ja numeroidut rotaatiot täytyy säilyttää erillisessä
arkistossa hallitun lokirotaation yhteydessä ennen tämän keruun aloitusta;
aikavyöhykettä ei arvata. Asennin ei kirjoita lokiasetuksia uudelleen.

Asennin ei lisää käyttäjää adm-, sudo- tai muihin lisäryhmiin eikä myönnä yleistä
lokien lukuoikeutta. Ylläpitäjä määrittää vain tarvittavien lokitiedostojen rajatut
lukuoikeudet ja niiden säilymisen lokirotaatiossa erikseen. Älä tee lokeista
yleisesti luettavia tai aja sovellusta jatkuvasti rootina.
UFW:n asennus, palomuurisäännöt ja lokituksen aktivointi tehdään erikseen säilyttäen
hallintayhteys. SSH-palvelinta tai sen asetuksia ei muuteta asennuksessa.

Jos konerekisteri on käytössä, täytä `config/identity.env` hyväksytyillä paikallisen
koneen lähde- ja kerääjätunnisteilla `config/identity.env.example`-mallin mukaan.
Tunnisteet rekisteröidään nykyisillä ylläpitofunktioilla; niitä ei päätellä nimestä
tai IP-osoitteesta. Säilytä asetustiedostojen oikeudet rajattuina.

## 4. Käyttöönoton tarkistus oikealla Debian-palvelimella

```bash
sudo crontab -u mysql_siem -l
sudo -u mysql_siem bash config/run_with_env.sh /usr/bin/python3 -m ingestion.ufw_to_mysql
sudo -u mysql_siem bash config/run_with_env.sh --ssh /usr/bin/python3 -m ingestion.auth.main
sudo -u mysql_siem bash config/run_with_env.sh --ssh /usr/bin/python3 -m detection.ssh_brute_force.main --automatic
sudo -u mysql_siem bash config/run_with_env.sh /usr/bin/python3 -m analysis.ufw.main --all --recent-hours 3
```

Keräyskomentojen rinnalla voi olla ajastettu ajo; lukituksen aiheuttama ohitus
on erotettava onnistuneesta keruusta. Varmista tietokannasta paikallisten
koetapahtumien tallentuminen ja UTC-mikrosekunnit sekä UFW-yhteenvetojen oikeat
ajanjaksot. Varmista myös järjestelmä-, tiedosto- ja turvallisuusmittareiden
päivittyminen nykyisissä cron-lokeissa ja tietokannassa. Tarkista lopuksi
uudelleenkäynnistyksen ja lokirotaation jälkeinen keruu. DNS tarkistetaan vain,
jos se on konfiguroitu.

MySQL 8.4.13:n migraatiot, käyttöoikeudet, `caching_sha2_password` ja sovellusyhteyden
UTC-istunto on todennettava siellä erikseen. Mintissä ajettavat komentojen
korvikkeisiin perustuvat asennustestit eivät todista oikeaa Debian-asennusta.
