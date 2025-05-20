# Dataplane Router

## Requirements:
	Pentru a simula o rețea virtuală vom folosi Mininet. Mininet este un simulator de rețele ce folosește în simulare implementari reale de kernel, switch și cod de aplicații.

`sudo apt update`

`sudo apt install mininet openvswitch-testcontroller tshark python3-click`

`python3-scapy xterm`

`sudo pip3 install mininet`

	Verificați să aveți instalat tshark.

	După ce am instalat Mininet, vom folosi următoarea comandă pentru a crește dimensiunea fontului în terminalele pe care le vom deschide.


`echo "xterm*font: *-fixed-*-*-*-18-*" >> ~/.Xresources`

`xrdb -merge ~/.Xresources`

## Descriere functionalitati - Router

Definesc functia de minim.
Definesc tipurile de pachete ip/arp.

1. **struct que_pack**:
Structura pentru pachetele care vor fi adaugate in coada, in care incapsulez interfata pe care o voi folosi ca sa trimitem pachetul.
2. **struct TrieNode**:
Structura pentru nodurile din trie, in care la finalul adresei adaug si ruta.
3. **TrieNode *create_node()**:
Alocarea unui nod in trie.
4. **swap_dest_source_ip**:
Functie de swap intre adresele sursa si destinatie pentru protocolul ip.
5. **swap_dest_source**:
Functie de swap intre adresele sursa si destinatie pentru protocolul ethernet.
6. **uint8_t *find_in_arp**:
Functie care cauta in tabela de arp, si returneaza adresa MAC corespunzatoare, altfel returneaza NULL.
7. **insert_route**:
Functie care insereaza o ruta in trie.
8. **lpm_lookup**:
Functie care cauta in trie ruta corespunzatoare adresei ip.
Folosind longest prefix match, parcurge arborel, si de fiecare cata cand gaseste un prefix mai lung updatez ruta.
9. **icmp_err**:
Calculam dimensiunea maxima de date icmp (headerul ip original si o parte din date).
Salvam o copie a pachetului original.
Inversam adresele sursa destinatie pentru ethernet si ip.
Setam parametrii pentru noul pachet ip.
Construim header ul icmp direct in buffer, dupa header ul IP.
Copiem datele originale dupa header ul icmp.
Calculam checksum ul icmp.
Calculam checksum-ul IP.
Trimitem pachetul.
10. **check_mac**:
Functie care verifica daca pachetul este pentru device ul curent, sau daca este un pachet broadcast.
11. **set_icmp**:
Functie care seteaza headerul icmp.
12. **set_ipv4_default**:
Functie care seteaza headerul ip default.
13. **find_next_hop**:
Cauta next hop pentru un pachet si actualizeaza mac ul destinatie daca este gasit in tabela arp.

14. **main**:
Do not modify this line.
Citesc tabela de rutare.
Crez trie-ul.
Insetez in trie toate rutele.
Creez coada pentru pachetele ale caror destinatie nu este in cache.
Creez tabela de ARP ( cache - ul).
Extragem headerul ethernet.
Verific daca pachetul este pentru device ul curent, sau daca este un pachet broadcast, altfel il ignor.
Verific tipul pachetului, daca este ip atunci.
Packet ip, extragem headerul ip.
Verific daca este un pachet icmp destinat routerului.
Extragem headerul icmp.
Verific daca este un pachet icmp de tip echo request.
Interschimba adresele pentru a crea un raspuns.
Trimitem pachetul icmp de raspuns.
Salvez checksum ul trecut.
Daca pachetul nu este pentru router, verific checksum ul.
Verific TTL ul.
Trimite un pachet icmp de eroare (time execeeded).
Cauta in tabela de rutare, si vezi daca ai vre un durm ( in cache ).
Daca nu am ruta.
Trimite un pachet ICMP de eroare.
Modific TTL si checksum doar daca am gasit ruta.
Print the checksum in hex.
Verific daca am in cache MAC ul lui next hop in cache. Daca l am, doar updatez headerul de ethernet si trimit.
Altfel, trebuie sa fac un ARP request.
Adaug in coada.
Construiesc headerul de ethernet pentru ARP request.
Trimite pachetul ARP.
Pachet ARP.
Extragem headerul ARP.
Caz in care ai request.
Interschimb adresele sursa si destinatie pentru ca raspunsul este inversul request ului.
La fel si la adresele mac.
Facem identic si la arp si ethernet.
Trimite pachetul ARP.
Este un replay.
Daca nu exista in cache, adaug in cache.
Proccesez pachetele din coada ( pe care pot si fac o coada temporara pentru pachertele care vor mai astepta).
Extrag headerul ip.
Daca gasesc next hop address in cache, atunci trimit.
Altfel, il pastrez in coada.
Eliberez coada veche.
Copiez elementele ramase inapoi in coada veche.
Altfel, ignor pachetul ( daca nu e nici pentru mine nici brodcast).