#ifndef ICMP_EXT_HDR_H
#define ICMP_EXT_HDR_H
struct pkt_icmphdr_t {
  uint8_t type;
  uint8_t code;
  uint16_t check;
} __attribute__((packed));

struct pkt_icmpunreachhdr_t {
  uint8_t unused1;
  uint8_t len; // 4-byte octets in network order
  uint16_t unused2;
} __attribute__((packed));

/* RFC 4884 ICMP Multi-part extension header:
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|      (Reserved)       |           Checksum            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct pkt_icmpexthdr_t {
  uint16_t version_reserved; /* 4 bits version, remainder is reserved */
  uint16_t check;
} __attribute__((packed));

#define PKT_ICMP_EXTENSION_VERSION 0x2000

/* RFC 4884 ICMP Multi-part object header:
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Length            |   Class-Num   |   C-Type      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                   // (Object payload) //                      |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct pkt_icmpobjhdr_t {
  uint16_t length;
  uint8_t class_num;
  uint8_t c_type;
} __attribute__((packed));

#endif
