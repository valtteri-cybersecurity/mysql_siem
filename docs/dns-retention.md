# DNS-historian säilytys

Tavallinen DNS-keruu ei enää poista MySQL:n `dns_events`-historiaa automaattisesti
30 päivän tai muun iän perusteella. Keruun jälkeinen `purge_events()`-kutsu on
poistettu. Muutos koskee myös olemassa olevia asetuksia, joissa on
`DNS_RETENTION_DAYS=30`: asetus ei käynnistä historian poistamista.

`DNS_RETENTION_DAYS` / `CollectorConfig.retention_days` säilyy yhteensopivuuden
vuoksi nykyisellä nimellään. Se rajaa edelleen AdGuardista haettavaa aikaväliä
ensimmäisellä ajolla ja tarkistaa, ettei valmistuneen keruun lukukohta ole
lähteen hakuikkunaa vanhempi. Oletus on tässä edelleen 30 päivää. Tämä on keruun
haku- ja palautumissuojaus, ei MySQL:ään tallennetun historian säilytysaika.
Suojaus voi edelleen vaatia manuaalista selvitystä pitkän keruukatkon jälkeen.

Keruutilaa, lähteitä, identiteettejä, suodatusta ja duplikaattisuojaa ei muuteta.
Jo tallennetut yli 30 päivän ikäiset tapahtumat säilyvät tavallisten keruuajojen
yli. Muutos ei palauta aiemmin poistettuja tapahtumia eikä muuta AdGuard Homen
omaa historian säilytystä.

`ingestion.dns.db.purge_events()` säilyy erillisenä, nimenomaisesti kutsuttavana
ylläpitofunktiona nykyisine parametreineen. Sen oletus on edelleen 30 päivää,
mikäli ylläpitäjä kutsuu sitä erikseen ilman säilytysaikaparametria. Tavallinen
keruu ei kutsu funktiota. Erillistä historianpoiston komentorivitoimintoa ei ole.
Manuaalinen poisto kohdistuu DNS-tapahtumiin, ei keruutilaan tai lähdeasetuksiin;
se poistaa myös kyseisten rivien duplikaattiavaimet, joten poistamisen vaikutus
mahdolliseen uusintakeruuseen on arvioitava ennen ylläpitotoimia.

Tapahtumahistorian pitkäaikainen säilytys kasvattaa tietokannan levytilantarvetta.
Seuraa levytilaa ja varmista tietokannan varmuuskopiointi. Lopullinen
pitkäaikaissäilytys ja mahdollinen automaattinen siivous suunnitellaan myöhemmin
erillisessä vaiheessa.
