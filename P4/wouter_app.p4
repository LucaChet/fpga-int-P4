#include <core.p4>
#include <xsa.p4>

const bit<16> INT_SHIM = 0x1234;
const bit<4> INT_MD = 0x3;
const bit<4> INT_VERSION = 0x2; // We use the int V2 spec

/*
 * Standard Ethernet header
 */
header ethernet_t {
    bit<48> dstAddr;       // Destination MAC address.
    bit<48> srcAddr;       // Source MAC address.
    bit<16> etherType;     // Ethernet type.
}

// header int_header_t {
// bit<4> ver;
// bit<1> D;
// bit<1> E;
// bit<1> M;
// bit<12> reserved;
// bit<5> hop_ml;
// bit<8> remaining_hop_cnt;
// bit<16> instruction_mask;
// bit<16> domain_id;
// bit<16> ds_instr;
// }

header int_t {
    bit<4> type;
    bit<1> G;
    bit<3> Rsvd;
    bit<8> length; // length without the int data and header!
    bit<16> next_protocol;
    bit<4> ver;
    bit<1> D;
    bit<1> E;
    bit<1> M;
    bit<12> reserved;
    bit<5> hop_ml;
    bit<8> remaining_hop_cnt;
    bit<16> instruction_mask;
    bit<16> domain_id;
    bit<16> ds_instr;
    bit<320> data;
    bit<320> data2;
    bit<320> data3;
    bit<320> data4;
    bit<320> data5;
    bit<320> data6;
    bit<128> data7;
}

struct headers {
    ethernet_t ethernet;
    int_t in_band;
}

// Define metadata structure for SmartNIC processing.
struct smartnic_metadata {
    bit<64> timestamp_ns;      // 64b timestamp (nanoseconds). Set when the packet arrives.
    bit<16> pid;               // 16b packet id for platform (READ ONLY - DO NOT EDIT).
    bit<3> ingress_port;       // 3b ingress port (0:CMAC0, 1:CMAC1, 2:HOST0, 3:HOST1).
    bit<3> egress_port;        // 3b egress port (0:CMAC0, 1:CMAC1, 2:HOST0, 3:HOST1).
    bit<1> truncate_enable;    // Reserved (tied to 0).
    bit<16> truncate_length;   // Reserved (tied to 0).
    bit<1> rss_enable;         // Reserved (tied to 0).
    bit<12> rss_entropy;       // Reserved (tied to 0).
    bit<4> drop_reason;        // Reserved (tied to 0).
    bit<32> scratch;           // Reserved (tied to 0).
}


// ****************************************************************************** //
// *************************** P A R S E R *************************************  //
// ****************************************************************************** //

// Define the parser state machine.
parser ParserImpl(packet_in packet, out headers hdr,
                  inout smartnic_metadata meta, inout standard_metadata_t smeta) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            INT_SHIM : parse_in_band;
            default: accept;
        }
    }

    state parse_in_band {
        packet.extract(hdr.in_band);
        transition accept;
    }
}

control MatchActionImpl(inout headers hdr, inout smartnic_metadata sn_meta,
                        inout standard_metadata_t smeta) {
    bit<64> data = 0;

    action send_back() {
        bit<48> tmp;
        hdr.in_band.remaining_hop_cnt = hdr.in_band.remaining_hop_cnt - 1;
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;
        sn_meta.egress_port = sn_meta.ingress_port;
    }

    action assign_1() {
        hdr.in_band.data[63:0] = data;
        send_back();
    }
    action assign_2() {
        hdr.in_band.data[127:64] = data;
        send_back();
    }
    action assign_3() {
        hdr.in_band.data[191:128] = data;
        send_back();
    }
    action assign_4() {
        hdr.in_band.data[255:192] = data;
        send_back();
    }
    action assign_5() {
        hdr.in_band.data[319:256] = data;
        send_back();
    }
    action assign_6() {
        hdr.in_band.data2[63:0] = data;
        send_back();
    }
    action assign_7() {
        hdr.in_band.data2[127:64] = data;
        send_back();
    }
    action assign_8() {
        hdr.in_band.data2[191:128] = data;
        send_back();
    }
    action assign_9() {
        hdr.in_band.data2[255:192] = data;
        send_back();
    }
    action assign_10() {
        hdr.in_band.data2[319:256] = data;
        send_back();
    }
    action assign_11() {
        hdr.in_band.data3[63:0] = data;
        send_back();
    }
    action assign_12() {
        hdr.in_band.data3[127:64] = data;
        send_back();
    }
    action assign_13() {
        hdr.in_band.data3[191:128] = data;
        send_back();
    }
    action assign_14() {
        hdr.in_band.data3[255:192] = data;
        send_back();
    }
    action assign_15() {
        hdr.in_band.data3[319:256] = data;
        send_back();
    }
    action assign_16() {
        hdr.in_band.data4[63:0] = data;
        send_back();
    }
    action assign_17() {
        hdr.in_band.data4[127:64] = data;
        send_back();
    }
    action assign_18() {
        hdr.in_band.data4[191:128] = data;
        send_back();
    }
    action assign_19() {
        hdr.in_band.data4[255:192] = data;
        send_back();
    }
    action assign_20() {
        hdr.in_band.data4[319:256] = data;
        send_back();
    }
    action assign_21() {
        hdr.in_band.data5[63:0] = data;
        send_back();
    }
    action assign_22() {
        hdr.in_band.data5[127:64] = data;
        send_back();
    }
    action assign_23() {
        hdr.in_band.data5[191:128] = data;
        send_back();
    }
    action assign_24() {
        hdr.in_band.data5[255:192] = data;
        send_back();
    }
    action assign_25() {
        hdr.in_band.data5[319:256] = data;
        send_back();
    }
    action assign_26() {
        hdr.in_band.data6[63:0] = data;
        send_back();
    }
    action assign_27() {
        hdr.in_band.data6[127:64] = data;
        send_back();
    }
    action assign_28() {
        hdr.in_band.data6[191:128] = data;
        send_back();
    }
    action assign_29() {
        hdr.in_band.data6[255:192] = data;
        send_back();
    }
    action assign_30() {
        hdr.in_band.data6[319:256] = data;
        send_back();
    }
    action assign_31() {
        hdr.in_band.data7[63:0] = data;
        send_back();
    }
    action assign_32() {
        hdr.in_band.data7[127:64] = data;
        send_back();
    }
    action drop() {
        smeta.drop = 1;
    }

    table assign {
        key = {
            hdr.in_band.remaining_hop_cnt: exact;
        }
        actions = {
            assign_1;
            assign_2;
            assign_3;
            assign_4;
            assign_5;
            assign_6;
            assign_7;
            assign_8;
            assign_9;
            assign_10;
            assign_11;
            assign_12;
            assign_13;
            assign_14;
            assign_15;
            assign_16;
            assign_17;
            assign_18;
            assign_19;
            assign_20;
            assign_21;
            assign_22;
            assign_23;
            assign_24;
            assign_25;
            assign_26;
            assign_27;
            assign_28;
            assign_29;
            assign_30;
            assign_31;
            assign_32;
        }
        size = 32;
        default_action = assign_1;
    }

    action add_pid() {
        data = (bit<64>) sn_meta.pid;
    }
    action add_timestamp() {
        data = sn_meta.timestamp_ns;
    }
    action add_ingress_port() {
        data = (bit<64>) sn_meta.ingress_port;
    }
    action add_egress_port() {
        data = (bit<64>) sn_meta.egress_port;
    }

    action add_dummy() {
        data = (bit<64>) 0x420;
    }

    action add_smeta_ingress_time() {
        data = smeta.ingress_timestamp;
    }

    table in_band_table {
        key = {
            hdr.in_band.ds_instr: exact;
        }
        actions = {
            add_pid;
            add_timestamp;
            add_ingress_port;
            add_egress_port;
            add_dummy;
            add_smeta_ingress_time;
            drop;
        }
        default_action = drop;
        size = 1024;
    }

    apply {
        if (hdr.in_band.isValid()) {
            if (hdr.in_band.type == INT_MD && hdr.in_band.remaining_hop_cnt > 0) {
                in_band_table.apply();
                assign.apply();
            }
            if (hdr.in_band.remaining_hop_cnt == 0) {
                hdr.in_band.M = 1;
            }
        }

        else {
            drop();
        }
    }

}
// Define the deparser logic.
control DeparserImpl(packet_out packet,
            in headers hdr, inout smartnic_metadata sn_meta, inout standard_metadata_t smeta){
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.in_band);

    }
}
// ****************************************************************************** //
// ******************************* M A I N ************************************ //
// ****************************************************************************** //
// Define the main pipeline.
XilinxPipeline(
    ParserImpl(),
    MatchActionImpl(),
    DeparserImpl()
) main;
