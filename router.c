#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// definesc functia de minim
#define min(a,b) ((a) < (b) ? (a) : (b))
// definesc tipurile de pachete ip/arp
#define IP_TYPE 0x0800
#define ARP_TYPE 0x0806

// structura pentru pachetele care vor fi adaugate in coada, in care incapsulez interfata pe care o voi folosi ca sa trimitem pachetul
struct que_pack{
	char buf[MAX_PACKET_LEN];
	int interface;
};

// structura pentru nodurile din trie, in care la finalul adresei adaug si ruta
struct TrieNode {
	struct TrieNode *children[2];
	struct route_table_entry *route;
};

// alocarea unui nod in trie
struct TrieNode *create_node() {
	struct TrieNode *node = (struct TrieNode *)calloc(1, sizeof(struct TrieNode));
	return node;
}

// functie de swap intre adresele sursa si destinatie pentru protocolul ip
void swap_dest_source_ip(struct ip_hdr *ip_hdr)
{
	uint32_t tmp;
	tmp = ip_hdr->dest_addr;
	ip_hdr->dest_addr = ip_hdr->source_addr;
	ip_hdr->source_addr = tmp;
}

// functie de swap intre adresele sursa si destinatie pentru protocolul ethernet
void swap_dest_source(struct ether_hdr *eth_hdr)
{
	uint8_t tmp[6];
	memcpy(tmp, eth_hdr->ethr_dhost, 6);
	memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
	memcpy(eth_hdr->ethr_shost, tmp, 6);
}


// functie care cauta in tabela de arp, si returneaza adresa MAC corespunzatoare, altfel returneaza NULL
uint8_t *find_in_arp (struct arp_table_entry arp_table[], int size, uint32_t ip) {
	for (int i = 0; i < size; i++) {
		if (arp_table[i].ip == ip) {
			return arp_table[i].mac;
		}
	}
	return NULL;
}

// functie care insereaza o ruta in trie
void insert_route(struct TrieNode *root, struct route_table_entry *entry) {
	uint32_t prefix = ntohl(entry->prefix);
	uint32_t mask = ntohl(entry->mask);

	int prefix_length = 0;
	while (mask & 0x80000000) {
		prefix_length++;
		mask <<= 1;
	}

	struct TrieNode *current = root;
	for (int i = 31; i >= 32 - prefix_length; i--) {
		int bit = (prefix >> i) & 1;
		if (!current->children[bit]) {
			current->children[bit] = create_node();
		}
		current = current->children[bit];
	}
	current->route = entry;
}

// functie care cauta in trie ruta corespunzatoare adresei ip
// folosind longest prefix match, parcurge arborel, si de fiecare cata cand gaseste un prefix mai lung updatez ruta
struct route_table_entry *lpm_lookup(struct TrieNode *root, uint32_t ip) {
	ip = ntohl(ip);
	struct TrieNode *current = root;
	struct route_table_entry *best_match = NULL;

	for (int i = 31; i >= 0; i--) {
		int bit = (ip >> i) & 1;
		if (!current) break;

		if (current->route) {
			best_match = current->route;
		}

		current = current->children[bit];
	}
	return best_match;
}


void icmp_err(char *buf, uint8_t type, uint8_t code, int interface, size_t len) {
    struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
    struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
    
    // calculam dimensiunea maxima de date icmp (headerul ip original si o parte din date)
    int icmp_data_len = min(64, len - sizeof(struct ether_hdr));
    
	// salvam o copie a pachetului original
    char orig_packet[icmp_data_len];
    memcpy(orig_packet, buf + sizeof(struct ether_hdr), icmp_data_len);
    
    // inversam adresele sursa destinatie pentru ethernet si ip
    swap_dest_source(eth_hdr);
    swap_dest_source_ip(ip_hdr);
    
    // setam parametrii pentru noul pachet ip
    ip_hdr->ttl = 64;
    ip_hdr->proto = 1;
    ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + icmp_data_len);
    
    // construim header ul icmp direct in buffer, dupa header ul IP
    struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
    icmp_hdr->mtype = type;
    icmp_hdr->mcode = code;
    icmp_hdr->check = 0;
    
    // copiem datele originale dupa header ul icmp
    memcpy(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), 
           orig_packet, icmp_data_len);
    
    // calculam checksum ul icmp
    icmp_hdr->check = checksum((uint16_t *)icmp_hdr, sizeof(struct icmp_hdr) + icmp_data_len);
    
    // calculam checksum-ul IP
    ip_hdr->checksum = 0;
    ip_hdr->checksum = checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));
    
    // trimitem pachetul
    size_t total_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + 
                        sizeof(struct icmp_hdr) + icmp_data_len;
    
    send_to_link(total_len, buf, interface);
}

// functie care verifica daca pachetul este pentru device ul curent, sau daca este un pachet broadcast
int check_mac(struct ether_hdr *eth_hdr, uint8_t *mac)
{
	int for_me = 1;

	for(int i = 0; i < 6; i++) {
		if(eth_hdr->ethr_dhost[i] != mac[i]) {
			for_me = 0;
			break;
		}
	}
	if(for_me == 0) {
		for(int i = 0; i < 6; i++) {
			if(eth_hdr->ethr_dhost[i] != 0xFF) {
				return 0;
			}
		}
	}
	return 1;
}

// functie care seteaza headerul icmp
void set_icmp(struct icmp_hdr *icmp_hdr, uint8_t type, uint8_t code){
	icmp_hdr->mtype = type;
	icmp_hdr->mcode = code;
	icmp_hdr->check = 0;
}

// functie care seteaza headerul ip default
void set_ipv4_default(struct ip_hdr *ip_hdr){
	ip_hdr->ver = 4;
	ip_hdr->ihl = 5;
	ip_hdr->tos = 0;
	ip_hdr->id = htons(1);
	ip_hdr->frag = 0;
	ip_hdr->ttl = 64;
	ip_hdr->checksum = 0;
	ip_hdr->tot_len = 0;
	ip_hdr->proto = 1;

}

// cauta next hop pentru un pachet si actualizeaza mac ul destinatie daca este gasit in tabela arp
int find_next_hop(struct TrieNode *trie_root, struct que_pack *current_pack, struct arp_table_entry arp_table[], int arp_table_len){
	struct ether_hdr *eth_hdr = (struct ether_hdr *) current_pack->buf;
	struct ip_hdr *ip_hdr = (struct ip_hdr *) (current_pack->buf + sizeof(struct ether_hdr));

	uint32_t dest_ip = ip_hdr->dest_addr;
	struct route_table_entry *route = lpm_lookup(trie_root, dest_ip);

	uint8_t *mac_i = find_in_arp(arp_table, arp_table_len, route->next_hop);

	if(mac_i != NULL){
		memcpy(eth_hdr->ethr_dhost, mac_i, 6);
		return 1;
	}
	return 0;
} 

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	// citesc tabela de rutare
	struct route_table_entry *route_table = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(route_table == NULL, "malloc");

	int rtable_size = read_rtable(argv[1], route_table);
	

	// crez trie-ul
	struct TrieNode *trie_root = create_node();
	DIE(trie_root == NULL, "malloc");
	
	// insertez in trie toate rutele
	for (int i = 0; i < rtable_size; i++) {
		insert_route(trie_root, &route_table[i]);
	}

	// creez coada pentru pachetele ale caror destinatie nu este in cache
	queue queue_a = create_queue();

	// creez tabela de ARP ( cache - ul)
	struct arp_table_entry arp_table[50];
	int arp_table_size = 0;

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);

		DIE(interface < 0, "recv_from_any_links");

		// extragem headerul ethernet
		struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;

		uint8_t mac[6];
		get_interface_mac(interface, mac);

		// verific daca pachetul este pentru device ul curent, sau daca este un pachet broadcast, altfel il ignor
		if(check_mac(eth_hdr, mac)) {
			// verific tipul pachetului, daca este ip atunci
			if(ntohs(eth_hdr->ethr_type) == IP_TYPE) {
				// packet ip, extragem headerul ip
				struct ip_hdr *ip_hdr = (struct ip_hdr *) (buf + sizeof(struct ether_hdr));
				
				// verific daca este un pachet icmp destinat routerului
				if(ip_hdr->proto == 1 && ip_hdr->dest_addr == inet_addr(get_interface_ip(interface))){
					
					// extragem headerul icmp
					struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(((void *)ip_hdr) + sizeof(struct ip_hdr));
					
					// verific daca este un pachet icmp de tip echo request
					if(icmp_hdr->mtype == 8 && icmp_hdr->mcode == 0){
						// Interschimba adresele pentru a crea un raspuns
						swap_dest_source(eth_hdr);
						swap_dest_source_ip(ip_hdr);

						ip_hdr->checksum = 0;
						ip_hdr->checksum = checksum((uint16_t *) ip_hdr, sizeof(struct ip_hdr));

						icmp_hdr->mtype = 0;
						icmp_hdr->check = 0;
						icmp_hdr->check = checksum((uint16_t *) icmp_hdr, sizeof(struct icmp_hdr));
						// trimitem pachetul icmp de raspuns
						send_to_link(len, buf, interface);
						continue;

					}

				}
				
				// salvez checksum ul trecut
				uint16_t old_checksum = ntohs(ip_hdr->checksum);
				ip_hdr->checksum = 0;
				// daca pachetul nu este pentru router, verific checksum ul
				if(checksum((uint16_t*) ip_hdr, sizeof(struct ip_hdr)) != old_checksum)
					continue;

				// verific TTL ul 
				if(ip_hdr->ttl <= 1){
					// trimite un pachet icmp de eroare (time execeeded)
					icmp_err(buf, 11, 0, interface, len);
					continue;
				}

				// cauta in tabela de rutare, si vezi daca ai vre un durm ( in cache )
				struct route_table_entry *route = lpm_lookup(trie_root, ip_hdr->dest_addr);
				// daca nu am ruta
				if(route == NULL){
					// trimite un pachet ICMP de eroare
					icmp_err(buf, 3, 0, interface, len);
					continue;
				}

				// modific TTL si checksum doar daca am gasit ruta
				ip_hdr->ttl--;
				ip_hdr->checksum = 0;
				// print the checksum in hex
				printf("Checksum: %x\n", ip_hdr->checksum);
				ip_hdr->checksum = htons(checksum((uint16_t *) ip_hdr, sizeof(struct ip_hdr)));
				printf("Checksum: %x\n", ip_hdr->checksum);


				// verific daca am in cache MAC ul lui next hop in cache. daca l am, doar updatez headerul de ethernet si trimit
				// altfel, trebuie sa fac un ARP request
				uint8_t *mac_i = find_in_arp(arp_table, arp_table_size, route->next_hop);

				if(mac_i != NULL){
					memcpy(eth_hdr->ethr_dhost, mac_i, 6);

					get_interface_mac(route->interface, eth_hdr->ethr_shost);
					send_to_link(len, buf, route->interface);
					continue;
				} else {
					get_interface_mac(route->interface, eth_hdr->ethr_shost);
					
					struct que_pack *new_pack = malloc(sizeof(struct que_pack));
					DIE(new_pack == NULL, "malloc");
					memcpy(new_pack->buf, buf, len);
					new_pack->interface = route->interface;

					// adaug in coada
					queue_enq(queue_a, new_pack);
				}

				// construiesc headerul de ethernet pentru ARP request
				struct ether_hdr *new_eth_hdr = (struct ether_hdr *) buf;
				new_eth_hdr->ethr_type = htons(ARP_TYPE);

				for(int i = 0; i < 6; i++){
					new_eth_hdr->ethr_dhost[i] = 0xFF;
				}

				get_interface_mac(route->interface, new_eth_hdr->ethr_shost);

				struct arp_hdr *new_arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

				new_arp_hdr->hw_type = htons(1);
				new_arp_hdr->proto_type = htons(IP_TYPE);
				new_arp_hdr->hw_len = 6;
				new_arp_hdr->proto_len = 4;
				new_arp_hdr->opcode = htons(1);

				memcpy(new_arp_hdr->shwa, new_eth_hdr->ethr_shost, 6);
				memcpy(new_arp_hdr->thwa, new_eth_hdr->ethr_dhost, 6);

				new_arp_hdr->sprotoa = inet_addr(get_interface_ip(route->interface));

				new_arp_hdr->tprotoa = route->next_hop;

				int arp_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
				// trimite pachetul ARP
				send_to_link(arp_len, buf, route->interface);
				
			} else{
				if(ntohs(eth_hdr->ethr_type) == ARP_TYPE){
					// pachet ARP
					// extragem headerul ARP
					struct arp_hdr *arp_hdr = (struct arp_hdr *) (((void *)eth_hdr) + sizeof(struct ether_hdr));

					if(ntohs(arp_hdr->opcode) == 1){
						// caz in care ai request
						arp_hdr->opcode = htons(2);
						
						uint32_t aux;

						// interschimb adresele sursa si destinatie pentru ca raspunsul este inversul request ului
						aux = arp_hdr->sprotoa;
						arp_hdr->sprotoa = arp_hdr->tprotoa;
						arp_hdr->tprotoa = aux;

						// la fel si la adresele mac
						//  facem identic si la arp si ethernet
						memcpy(arp_hdr->thwa, arp_hdr->shwa, 6);
						memcpy(arp_hdr->shwa, mac, 6);
						
						memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
						memcpy(eth_hdr->ethr_shost, mac, 6);

						// trimite pachetul ARP
						int arp_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
						send_to_link(arp_len, buf, interface);

					} else {
						if(ntohs(arp_hdr->opcode) == 2){
							// este un replay
							struct arp_table_entry *new_arp_entry = malloc(sizeof(struct arp_table_entry));
							DIE(new_arp_entry == NULL, "malloc");

							new_arp_entry->ip = arp_hdr->sprotoa;
							memcpy(new_arp_entry->mac, arp_hdr->shwa, 6);
						
							uint8_t *mac_i = find_in_arp(arp_table, arp_table_size, new_arp_entry->ip);
							// daca nu exista in cache, adaug in cache
							if(mac_i == NULL){
								arp_table[arp_table_size] = *new_arp_entry;
								arp_table_size++;
								
								// proccesez pachetele din coada ( pe care pot si fac o coada temporara pentru pachertele care vor mai astepta)
								queue temp = create_queue();

								while(!queue_empty(queue_a)){
									struct que_pack *temp_pack = (struct que_pack *)queue_deq(queue_a);

									// daca gasesc next hop address in cache, atunci trimit
									if(find_next_hop(trie_root, temp_pack, arp_table, arp_table_size)){
										send_to_link(len, temp_pack->buf, temp_pack->interface);
									} else {
										// altfel, il pastrez in coada
										queue_enq(temp, temp_pack);
									}
									

								}
								// eliberez coada veche
								free(queue_a);
								// copiez elementele ramase inapoi in coada veche
								queue_a = temp;

							}

						}
					}

				}
			}
			// altfel, ignor pachetul ( daca nu e nici pentru mine nici brodcast)
		} else {
			continue;
		}
	}
}