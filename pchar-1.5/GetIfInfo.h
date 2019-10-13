// -*- c++ -*-
// $Id: GetIfInfo.h 1082 2005-02-12 19:40:04Z bmah $
//

#ifndef GETIFINFO_H
#define GETIFINFO_H

#include "Pctest.h"

class GetIfInfo
{
public:
  GetIfInfo(void *, Pctest *);

  ~GetIfInfo();

  bool	IsValid(void);

  const char *	GetDescription(void) const;
  const char *	GetIfInfo::GetName(void) const;
  const char *	GetContact(void) const;
  const char *	GetLocation(void) const;
  const char *	GetIfDescription(void) const;
  uint32_t	 	GetIfMtu(void) const;
  uint32_t 		GetIfSpeed(void) const;
  uint32_t 		GetIfType(void) const;
  const char *	GetIfTypeString(void) const;

protected:
  char *	Description;
  char *	Name;
  char *	Contact;
  char *	Location;
  char *	IfDescription;
  uint32_t	IfMtu;
  uint32_t	IfSpeed;
  int		IfType;

  bool	valid_info;

private:

};

#endif /* GETIFINFO_H */
