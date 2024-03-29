/*
 * pando.c
 *
 * Copyright (C) 2014 Tomasz Bujlow <tomasz@skatnet.dk>
 *
 * The signature is based on the Libprotoident library.
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <linux/netfilter/ndpi/ndpi_protocol_ids.h>

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_PANDO

#include <linux/netfilter/ndpi/ndpi_api.h>

static void ndpi_int_pando_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_PANDO, NDPI_PROTOCOL_UNKNOWN);
}

static void ndpi_check_pando_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	u_int32_t payload_len = packet->payload_packet_len;

	if (ndpi_match_strprefix(packet->payload, payload_len, "\x0ePan")) {
	    NDPI_LOG_INFO(ndpi_struct, "Found PANDO\n");
	    ndpi_int_pando_add_connection(ndpi_struct, flow);
	}
}

static void ndpi_check_pando_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	u_int32_t payload_len = packet->payload_packet_len;

	/* Check if we so far detected the protocol in the request or not. */
	NDPI_LOG_DBG2(ndpi_struct, "PANDO stage %u: \n", flow->pando_stage);
	if (flow->pando_stage == 0) {

		if ((payload_len >= 4) && (packet->payload[0] == 0x00) && (packet->payload[1] == 0x00) && (packet->payload[2] == 0x00) && (packet->payload[3] == 0x09)) {
			NDPI_LOG_DBG2(ndpi_struct, "Possible PANDO request detected, we will look further for the response..\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->pando_stage = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
			return;
		}

		if (ndpi_match_strprefix(packet->payload, payload_len, "UDPA")) {
			NDPI_LOG_DBG2(ndpi_struct, "Possible PANDO request detected, we will look further for the response..\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->pando_stage = packet->packet_direction + 3; // packet_direction 0: stage 3, packet_direction 1: stage 4
			return;
		}

		if (ndpi_match_strprefix(packet->payload, payload_len, "UDPR") || ndpi_match_strprefix(packet->payload, payload_len, "UDPE")) {
			NDPI_LOG_DBG2(ndpi_struct, "Possible PANDO request detected, we will look further for the response..\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->pando_stage = packet->packet_direction + 5; // packet_direction 0: stage 5, packet_direction 1: stage 6
			return;
		}

	} else if ((flow->pando_stage == 1) || (flow->pando_stage == 2)) {

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->pando_stage - packet->packet_direction) == 1) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if ((payload_len == 0) || ((payload_len >= 4) && (packet->payload[0] == 0x00) && (packet->payload[1] == 0x00) && (packet->payload[2] == 0x00) && (packet->payload[3] == 0x09))) {
			NDPI_LOG_INFO(ndpi_struct, "found PANDO\n");
			ndpi_int_pando_add_connection(ndpi_struct, flow);
		} else {
			NDPI_LOG_DBG2(ndpi_struct, "The reply did not seem to belong to PANDO, resetting the stage to 0..\n");
			flow->pando_stage = 0;
		}

	} else if ((flow->pando_stage == 3) || (flow->pando_stage == 4)) {

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->pando_stage - packet->packet_direction) == 3) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if ((payload_len == 0) || (ndpi_match_strprefix(packet->payload, payload_len, "UDPR") || ndpi_match_strprefix(packet->payload, payload_len, "UDPE"))) {
			NDPI_LOG_INFO(ndpi_struct, "found PANDO\n");
			ndpi_int_pando_add_connection(ndpi_struct, flow);
		} else {
			NDPI_LOG_DBG2(ndpi_struct, "The reply did not seem to belong to PANDO, resetting the stage to 0..\n");
			flow->pando_stage = 0;
		}

	} else if ((flow->pando_stage == 5) || (flow->pando_stage == 6)) {

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->pando_stage - packet->packet_direction) == 5) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if (ndpi_match_strprefix(packet->payload, payload_len, "UDPA")) {
			NDPI_LOG_INFO(ndpi_struct, "found PANDO\n");
			ndpi_int_pando_add_connection(ndpi_struct, flow);
		} else {
			NDPI_LOG_DBG2(ndpi_struct, "The reply did not seem to belong to PANDO, resetting the stage to 0\n");
			flow->pando_stage = 0;
		}
	}
}

void ndpi_search_pando(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;

	NDPI_LOG_DBG(ndpi_struct, "search PANDO\n");
	/* Break after 20 packets. */
	if (flow->packet_counter > 20) {
		NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
		return;
	}

	/* skip marked or retransmitted packets */
	if (packet->tcp_retransmission != 0) {
		return;
	}

	if (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_PANDO) {
		return;
	}

	ndpi_check_pando_tcp(ndpi_struct, flow);

	if (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_PANDO) {
	    return;
	}

	ndpi_check_pando_udp(ndpi_struct, flow);
}


void init_pando_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Pando_Media_Booster", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_PANDO,
				      ndpi_search_pando,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
