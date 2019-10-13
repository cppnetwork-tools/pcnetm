// -*- c++ -*-
// $Id: GetIfInfo.cc 1082 2005-02-12 19:40:04Z bmah $
//

#include <stdio.h>

#ifdef STDC_HEADERS
#include <stdlib.h>
#endif /* STDC_HEADERS */

#ifdef HAVE_UNISTD_H 
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */

#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "pc.h"

// UCD SNMP includes
#include "ucd-snmp/ucd-snmp-config.h"
#include "ucd-snmp/asn1.h"
#include "ucd-snmp/snmp_api.h"
#include "ucd-snmp/snmp_impl.h"
#include "ucd-snmp/snmp_client.h"
#include "ucd-snmp/mib.h"
#include "ucd-snmp/snmp.h"
#include "ucd-snmp/system.h"
#include "ucd-snmp/default_store.h"

#include "GetIfInfo.h"
#include "Pctest.h"

static oid *snmp_parse_oid(char *argv, oid *root, size_t *rootlen);

oid * snmp_parse_oid(char *argv,	oid *root, size_t *rootlen)
{
size_t savlen = *rootlen;

if (read_objid(argv,root,rootlen)) {
    return root;
    }

*rootlen = savlen;
if (get_node(argv,root,rootlen)) {
    return root;
    }

return NULL;
}

GetIfInfo::GetIfInfo(void *addr, Pctest *pct) :
			  valid_info(false),
			  Description(NULL),
			  Name(NULL),
			  Contact(NULL),
			  Location(NULL),
			  IfDescription(NULL),
			  IfMtu(0),
			  IfSpeed(0),
			  IfType(0)
{
struct snmp_session session, *ssess;
struct snmp_pdu *pdu;
struct snmp_pdu *response;
struct variable_list *vars;

char *community = "public";

char *intoap;
long ifnumber;

oid name_oid[MAX_OID_LEN];
int status;
size_t name_length;
size_t ndx;
size_t ilen;

char cbuff[128];

typedef enum
  {
  SysDescr_AVBI		= 0,
  SysContact_AVBI	= 1,
  SysName_AVBI		= 2,
  SysLocation_AVBI	= 3,
  IfIndex_AVBI		= 4,
  AVBI_COUNT		= 5
  } query_a_vb_index_e;

char *query_A_names[AVBI_COUNT] =
	{
	"system.sysDescr.0",
	"system.sysContact.0",
	"system.sysName.0",
	"system.sysLocation.0",
    0
	};

typedef enum
  {
  ifDescr_BVBI		= 0,
  ifType_BVBI		= 1,
  ifMtu_BVBI		= 2,
  ifSpeed_BVBI		= 3,
  BVBI_COUNT		= 4
  } query_b_vb_index_e;

char *query_B_names_master[BVBI_COUNT] =
	{
	"interfaces.ifTable.ifEntry.ifDescr.",
	"interfaces.ifTable.ifEntry.ifType.",
	"interfaces.ifTable.ifEntry.ifMtu.",
	"interfaces.ifTable.ifEntry.ifSpeed."
	};

char *query_B_names[BVBI_COUNT];

/* initialize session to default values */
snmp_sess_init(&session);

/* read in MIB database and initialize the snmp library*/
init_snmp("snmpapp");

if (session.version == SNMP_DEFAULT_VERSION)
  {
  session.version = ds_get_int(DS_LIBRARY_ID, DS_LIB_SNMPVERSION);
  }

/* make our engineID something other than what the localhost might
 * be using, otherwise the automatic v3 time-synchronization won't work */
//setup_engineID(NULL, "a bogus text string");

 intoap = pct->GetPrintableAddress(addr);
session.peername = new char[strlen(intoap)+1];
if (session.peername == NULL)
  {
  SOCK_CLEANUP;
  }
strcpy(session.peername, intoap);

session.community = (unsigned char *)community;
session.community_len = strlen(community);

strcpy(cbuff, "ip.ipAddrTable.ipAddrEntry.ipAdEntIfIndex.");
strcat(cbuff, pct->GetPrintableAddress(addr));
query_A_names[IfIndex_AVBI] = cbuff;

SOCK_STARTUP;

ssess = snmp_open(&session);
if (ssess == NULL)
   {
   snmp_sess_perror("snmpget", &session);
   SOCK_CLEANUP;
   }

pdu = snmp_pdu_create(SNMP_MSG_GET);
for (ndx = 0; ndx < AVBI_COUNT; ndx++)
  {
  name_length = MAX_OID_LEN;
  if (!snmp_parse_oid(query_A_names[ndx], name_oid, &name_length))
     {
     snmp_close(ssess);
	 SOCK_CLEANUP;
	 }
  snmp_add_null_var(pdu, name_oid, name_length);
  }

response = NULL;
status = snmp_synch_response(ssess, pdu, &response);
if ((status == STAT_SUCCESS) && (response->errstat == SNMP_ERR_NOERROR))
  {
  for (ndx = 0, vars = response->variables; vars; ndx++, vars = vars->next_variable)
	{
    if (ndx == IfIndex_AVBI)
	  {
	  ifnumber = *(vars->val.integer);
	  }
	else {
	     char *nsp;
		 nsp = new char[vars->val_len + 1];
		 strncpy(nsp, (char *)(vars->val.string), vars->val_len);
		 nsp[vars->val_len] = '\0';
	     switch (ndx)
		   {
		   case SysDescr_AVBI:
			    Description = nsp;
				break;
		   case SysContact_AVBI:
			    Contact = nsp;
				break;
		   case SysName_AVBI:
		        Name = nsp;
				break;
		   case SysLocation_AVBI:
		        Location = nsp;
				break;
		   default:
			    delete nsp;
		   }
	     }
	}

  sprintf(cbuff, "%lu", ifnumber);
  ilen = strlen(cbuff);
  for (ndx = 0; ndx < BVBI_COUNT; ndx++)
	{
	query_B_names[ndx] = new char[ilen + strlen(query_B_names_master[ndx]) + 1];
	strcpy(query_B_names[ndx], query_B_names_master[ndx]);
	strcat(query_B_names[ndx], cbuff);
	}

  snmp_free_pdu(response);
  response = NULL;

  pdu = snmp_pdu_create(SNMP_MSG_GET);
  for (ndx = 0; ndx < BVBI_COUNT; ndx++)
	{
	name_length = MAX_OID_LEN;
	if (!snmp_parse_oid(query_B_names[ndx], name_oid, &name_length))
	  {
	  goto cleanup;
	  }
	snmp_add_null_var(pdu, name_oid, name_length);
	}

  status = snmp_synch_response(ssess, pdu, &response);
  if ((status == STAT_SUCCESS) && (response->errstat == SNMP_ERR_NOERROR))
	{
	for (ndx = 0, vars = response->variables; vars; ndx++, vars = vars->next_variable)
	  {
       switch (ndx)
		 {
		 case ifDescr_BVBI:
		      IfDescription = new char[vars->val_len + 1];
			  strncpy(IfDescription, (char *)(vars->val.string), vars->val_len);
			  IfDescription[vars->val_len] = '\0';
			  break;

		 case ifType_BVBI:
		      IfType = *(vars->val.integer);
			  break;

		 case ifMtu_BVBI:
		      IfMtu = *(vars->val.integer);
			  break;

		 case ifSpeed_BVBI:
		      IfSpeed = *(vars->val.integer);
		      break;
		 }
	  }
	}
  valid_info = true;
  }

cleanup:

if (response)
  {
  snmp_free_pdu(response);
  }
snmp_close(ssess);
SOCK_CLEANUP;
}

GetIfInfo::~GetIfInfo()
{
if (Description) delete Description;
if (Name) delete Name;
if (Contact) delete Contact;
if (Location) delete Location;
if (IfDescription) delete IfDescription;
}

const char unknown_str[] = "-unknown-";

const char *
GetIfInfo::GetDescription(void) const
{
if (!valid_info)
  {
  return unknown_str;
  }
return Description;
}

const char *
GetIfInfo::GetName(void) const
{
if (!valid_info)
  {
  return unknown_str;
  }
return Name;
}

const char *
GetIfInfo::GetContact(void) const
{
if (!valid_info)
  {
  return unknown_str;
  }
return Contact;
}

const char *GetIfInfo::GetLocation(void) const
{
if (!valid_info)
  {
  return unknown_str;
  }
return Location;
}

const char *
GetIfInfo::GetIfDescription(void) const
{
if (!valid_info)
  {
  return unknown_str;
  }
return IfDescription;
}

uint32_t
GetIfInfo::GetIfMtu(void) const
{
if (!valid_info)
  {
  return 0;
  }
return IfMtu;
}

uint32_t
GetIfInfo::GetIfSpeed(void) const
{
if (!valid_info)
  {
  return 0;
  }
return IfSpeed;
}

uint32_t
GetIfInfo::GetIfType(void) const
{
if (!valid_info)
  {
  return 0;
  }
return IfType;
}

const char *iftype_strs[] =
	{
    "other",				//	=  1,	//-- none of the following
	"regular1822",			//	=  2,
	"hdh1822",				//	=  3,
	"ddn-x25",				//	=  4,
	"rfc877-x25",			//	=  5,
	"ethernet-csmacd",		//	=  6,
	"iso88023-csmacd",		//	=  7,
	"iso88024-tokenBus",	//	=  8,
	"iso88025-tokenRing",	//	=  9,
	"iso88026-man",			//	=  10,
	"starLan",				//	=  11,
	"proteon-10Mbit",		//	=  12,
	"proteon-80Mbit",		//	=  13,
	"hyperchannel",			//	=  14,
	"fddi",					//	=  15,
	"lapb",					//	=  16,
	"sdlc",					//	=  17,
	"ds1",					//	=  18,  // -- T-1
	"e1",					//	=  19,  // -- european equiv. of T-1
	"basicISDN",			//	=  20,
	"primaryISDN",			//	=  21,  // -- proprietary serial
	"propPointToPointSerial",//	=  22,
	"ppp",					//	=  23,
	"softwareLoopback",		//	=  24,
	"eon",					//	=  25,  // -- CLNP over IP [11]
	"ethernet-3Mbit",		//	=  26,
	"nsip",					//	=  27,  // -- XNS over IP
	"slip",					//	=  28,  // -- generic SLIP
	"ultra",				//	=  29,  // -- ULTRA technologies
	"ds3",					//	=  30,  // -- T-3
	"sip"					//	=  31   // -- SMDS
	};

const size_t num_iftype_strs = sizeof(iftype_strs)/sizeof(char *);

const char *
GetIfInfo::GetIfTypeString(void) const
{
if (!valid_info)
  {
  return unknown_str;
  }

if ((IfType == 0 ) || (IfType > num_iftype_strs))
  {
  return unknown_str;
  }
return iftype_strs[IfType-1];
}




