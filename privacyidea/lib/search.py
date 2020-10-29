import traceback
import string
import datetime
import os
import logging
from six import string_types
from dateutil import parser

from sqlalchemy import (and_, or_, func)
from sqlalchemy.orm import aliased

from privacyidea.lib.token import (_create_token_query, create_tokenclass_object)
from privacyidea.lib.error import (TokenAdminError,
                                   ParameterError,
                                   privacyIDEAError, ResourceNotFoundError)
from privacyidea.lib.decorators import (check_user_or_serial,
                                        check_copy_serials)
from privacyidea.lib.tokenclass import TokenClass
from privacyidea.lib.log import log_with
from privacyidea.models import (Token, Realm, TokenRealm, Challenge,
                                MachineToken, TokenInfo, TokenOwner)
from privacyidea.lib.config import (get_token_class, get_token_prefix,
                                    get_token_types, get_from_config,
                                    get_inc_fail_count_on_false_pin, SYSCONF)
from privacyidea.lib.user import User
from privacyidea.lib import _
from privacyidea.lib.realm import realm_is_defined
from privacyidea.lib.resolver import get_resolver_object
from privacyidea.lib.policydecorators import (libpolicy,
                                              auth_user_does_not_exist,
                                              auth_user_has_no_token,
                                              auth_user_passthru,
                                              auth_user_timelimit,
                                              auth_lastauth,
                                              auth_cache,
                                              config_lost_token,
                                              reset_all_user_tokens)
from privacyidea.lib.tokenclass import DATE_FORMAT
from privacyidea.lib.tokenclass import TOKENKIND
from dateutil.tz import tzlocal

log = logging.getLogger(__name__)

optional = True
required = False

ENCODING = "utf-8"

DEVICE_TYPE_TABLE = aliased(TokenInfo)
DEVICE_SERIAL_TABLE = aliased(TokenInfo)
VALIDITY_PERIOD_END_TABLE = aliased(TokenInfo)
VALIDITY_PERIOD_START_TABLE = aliased(TokenInfo)
USER_ID_TABLE = aliased(TokenOwner)

# for sorting by tokeninfo columns
DEVICE_TYPE_COL = DEVICE_TYPE_TABLE.Value
DEVICE_SERIAL_COL = DEVICE_SERIAL_TABLE.Value
VALIDITY_PERIOD_END_COL = VALIDITY_PERIOD_END_TABLE.Value
VALIDITY_PERIOD_START_COL = VALIDITY_PERIOD_START_TABLE.Value
USER_ID_COL = USER_ID_TABLE.user_id

# coalesce 
COALESCED_SERIAL_COL = func.coalesce(DEVICE_SERIAL_TABLE.Value, Token.serial)
COALESCED_TYPE_COL = func.coalesce(DEVICE_TYPE_TABLE.Value, Token.tokentype)

def search_add_token_filter(sql_query=None, search_filter=None):
    name = search_filter.get("name", None)
    value = search_filter.get("value", None)

    if not sql_query or not name:
        return sql_query

    if name == "active":
        sql_query = sql_query.filter(Token.active == (value is True))
    elif name == "revoked":
        sql_query = sql_query.filter(Token.revoked == (value is True))
    elif name == "locked":
        sql_query = sql_query.filter(Token.locked == (value is True))
    elif name == "userid":
        if value.strip("*"):
            sql_query = sql_query.filter(USER_ID_TABLE.user_id.like(value.replace("*", "%")))
    elif name == "validity_period_end_from":
        sql_query = sql_query.filter(func.date(VALIDITY_PERIOD_END_TABLE.Value) >= func.date(value))
    elif name == "validity_period_end_to":
        sql_query = sql_query.filter(func.date(VALIDITY_PERIOD_END_TABLE.Value) <= func.date(value))
    elif name == "validity_period_start_from":
        sql_query = sql_query.filter(func.date(VALIDITY_PERIOD_START_TABLE.Value) >= func.date(value))
    elif name == "validity_period_start_to":
        sql_query = sql_query.filter(func.date(VALIDITY_PERIOD_START_TABLE.Value) <= func.date(value))
    elif name == "serial":
        if value.strip("*"):
            sql_query = sql_query.filter(Token.serial.like(value.replace("*", "%")))
    elif name == "deviceSerial":
        if value.strip("*"):
            sql_query = sql_query.filter(or_(Token.serial.like(value.replace("*", "%")), DEVICE_SERIAL_TABLE.Value.like(value.replace("*", "%"))))
    elif name == "deviceType":
        if value.strip("*"):
            sql_query = sql_query.filter(DEVICE_TYPE_TABLE.Value.like(value.replace("*", "%")))
    elif name == "tokentype":
        if value.strip("*"):
            sql_query = sql_query.filter(or_(Token.tokentype.like(value.lower().replace("*", "%")), DEVICE_TYPE_TABLE.Value.like(value.replace("*", "%"))))

    return sql_query
            
def search_create_token_query(filters=None):
    sql_query = Token.query

    # to sort by token info columns
    sql_query = sql_query.outerjoin(DEVICE_TYPE_TABLE, and_(DEVICE_TYPE_TABLE.token_id == Token.id, DEVICE_TYPE_TABLE.Key == "deviceType"))
    sql_query = sql_query.outerjoin(DEVICE_SERIAL_TABLE, and_(DEVICE_SERIAL_TABLE.token_id == Token.id, DEVICE_SERIAL_TABLE.Key == "deviceSerial"))
    sql_query = sql_query.outerjoin(VALIDITY_PERIOD_END_TABLE, and_(VALIDITY_PERIOD_END_TABLE.token_id == Token.id, VALIDITY_PERIOD_END_TABLE.Key == "validity_period_end"))
    sql_query = sql_query.outerjoin(VALIDITY_PERIOD_START_TABLE, and_(VALIDITY_PERIOD_START_TABLE.token_id == Token.id, VALIDITY_PERIOD_START_TABLE.Key == "validity_period_start"))
    sql_query = sql_query.outerjoin(USER_ID_TABLE, and_(USER_ID_TABLE.token_id == Token.id))

    sql_query = sql_query.add_column(DEVICE_TYPE_COL)
    sql_query = sql_query.add_column(DEVICE_SERIAL_COL)
    sql_query = sql_query.add_column(VALIDITY_PERIOD_END_COL)
    sql_query = sql_query.add_column(VALIDITY_PERIOD_START_COL)
    sql_query = sql_query.add_column(COALESCED_SERIAL_COL)
    sql_query = sql_query.add_column(COALESCED_TYPE_COL)
    sql_query = sql_query.add_column(USER_ID_COL)

    for f in filters:
        sql_query = search_add_token_filter(sql_query, f)

    return sql_query


@log_with(log)
def get_tokens_paginate_no_ldap(tokentype=None, realm=None, assigned=None, user=None,
                serial=None, active=None, revoked=None, locked=None, resolver=None, rollout_state=None,
                sortby=Token.serial, sortdir="asc", psize=15,
                page=1, description=None, userid=None, allowed_realms=None,
                deviceType=None, deviceSerial=None,
                validity_period_end_from=None, validity_period_end_to=None,
                validity_period_start_from=None, validity_period_start_to=None):
    """
    This function is used to retrieve a token list, that can be displayed in
    the Web UI. It supports pagination.
    Each retrieved page will also contain a "next" and a "prev", indicating
    the next or previous page. If either does not exist, it is None.

    :param tokentype:
    :param realm:
    :param assigned: Returns assigned (True) or not assigned (False) tokens
    :type assigned: bool
    :param user: The user, whose token should be displayed
    :type user: User object
    :param serial: a pattern for matching the serial
    :param active:
    :param resolver: A resolver name, which may contain "*" for filtering.
    :type resolver: basestring
    :param userid: A userid, which may contain "*" for filtering.
    :type userid: basestring
    :param rollout_state:
    :param sortby: Sort by a certain Token DB field. The default is
        Token.serial. If a string like "serial" is provided, we try to convert
        it to the DB column.
    :type sortby: A Token column or a string.
    :param sortdir: Can be "asc" (default) or "desc"
    :type sortdir: basestring
    :param psize: The size of the page
    :type psize: int
    :param page: The number of the page to view. Starts with 1 ;-)
    :type page: int
    :param allowed_realms: A list of realms, that the admin is allowed to see
    :type allowed_realms: list
    :return: dict with tokens, prev, next and count
    :rtype: dict
    """
    sql_query = _create_token_query(tokentype=tokentype, realm=realm,
                                assigned=assigned, user=user,
                                serial_wildcard=serial, active=active, revoked=revoked, locked=locked,
                                resolver=resolver,
                                rollout_state=rollout_state,
                                description=description, userid=userid,
                                allowed_realms=allowed_realms)

    if isinstance(sortby, string_types):
        # convert the string to a Token column
        cols = Token.__table__.columns
        sortby = cols.get(sortby)

    if sortdir == "desc":
        sql_query = sql_query.order_by(sortby.desc())
    else:
        sql_query = sql_query.order_by(sortby.asc())

    pagination = sql_query.paginate(page, per_page=psize,
                                    error_out=False)
    tokens = pagination.items
    prev = None
    if pagination.has_prev:
        prev = page-1
    next = None
    if pagination.has_next:
        next = page + 1
    token_list = []
    for token in tokens:
        tokenobject = create_tokenclass_object(token)
        if isinstance(tokenobject, TokenClass):
            token_dict = tokenobject.get_as_dict()
            token_dict["username"] = token_dict["user_id"]
            token_dict["user_realm"] = ""

            token_list.append(token_dict)

    ret = {"tokens": token_list,
           "prev": prev,
           "next": next,
           "current": page,
           "count": pagination.total}
    return ret

def get_col_order(sortby=None, sortdir=None):
    cols = Token.__table__.columns
    default_col = Token.serial

    sort_column_mapper = {
        "deviceSerial": COALESCED_SERIAL_COL,
        "validity_period_start": VALIDITY_PERIOD_START_COL,
        "validity_period_end": VALIDITY_PERIOD_END_COL,
        "deviceType": COALESCED_TYPE_COL,
        "userid": USER_ID_COL,
        "active": Token.active,
        "serial": Token.serial,
        "tokentype": Token.tokentype
    }

    sortby = sort_column_mapper.get(sortby, default_col)
    if sortby == Token.active:
        sortdir = "asc" if sortdir == "desc" else "desc"

    return sortby, sortdir

def is_valid_filter(name=None, operation=None):
    allowed_filters = [
        "serial",
        "deviceSerial",
        "deviceType",
        "active",
        "revoked",
        "locked",
        "userid",
        "tokentype",
        "validity_period_start",
        "validity_period_end"
    ]
    return name in allowed_filters

def get_query_search_name(name=None, operation=None):
    if not is_valid_filter(name, operation):
        return None

    name_to_operation_mapper = {
        "validity_period_start": {
            "after": "validity_period_start_from",
            "before": "validity_period_start_to"
        },
        "validity_period_end": {
            "after": "validity_period_end_from",
            "before": "validity_period_end_to"
        }
    }

    name_to_operation = name_to_operation_mapper.get(name)
    if name_to_operation:
        return name_to_operation.get(operation, None)
    return name

def get_query_search_value(name=None, value=None, operation=None):
    value = value.replace("*","").replace("%","")
    
    if name == "active" or name == "revoked" or name == "locked":
        value = value == "true"

    if operation == "contains":
        value = "*" + value + "*"
    elif operation == "startswith":
        value = value + "*"
    elif operation == "endswith":
        value = "*" + value
    
    return value

@log_with(log)
def get_search_groups_paginate_no_ldap(searchRequestDetails=None):
    union_queries = None

    for search_group in searchRequestDetails["searchGroups"]:
        filters = []
        for search_filter in search_group["filters"]:
            queryOperation = search_filter.get("operation", "equals")
            
            queryName = search_filter.get("name", None)
            queryName = get_query_search_name(queryName, queryOperation)
            if not queryName:
                continue

            queryValue = search_filter.get("values", [])[0]
            if not queryValue:
                continue
            queryValue = get_query_search_value(queryName, queryValue, queryOperation)

            filters.append({"name": queryName, "value": queryValue})

        if not filters:
            continue

        sql_query = search_create_token_query(filters)

        if union_queries:
            union_queries = union_queries.union(sql_query)
            continue
        union_queries = sql_query
    
    limit = searchRequestDetails.get("limit", 5)
    offset = searchRequestDetails.get("offset", 0)
    total_count = 0
    has_next = False
    token_list = []
    
    if union_queries:
        # How sql_alchemy handles total count https://github.com/pallets/flask-sqlalchemy/blob/master/src/flask_sqlalchemy/__init__.py
        total_count = union_queries.count()

        sortby = searchRequestDetails.get("sortBy", "deviceSerial")
        sortdir = searchRequestDetails.get("sortDir", "asc")

        if isinstance(sortby, string_types):
            sortby, sortdir = get_col_order(sortby=sortby, sortdir=sortdir)

        if sortby is not None:
            union_queries = union_queries.order_by(sortby.desc(), Token.id.asc()) if sortdir == "desc" else union_queries.order_by(sortby.asc(), Token.id.asc())

        union_queries = union_queries.slice(offset, offset+limit)
        tokens = union_queries.all()

        has_next = len(tokens) + offset < total_count

        for token_and_tokeninfo in tokens:
            # token_and_tokeninfo[0]: only getting token, not tokeninfo columns from query
            token = token_and_tokeninfo[0]
            tokenobject = create_tokenclass_object(token)
            if isinstance(tokenobject, TokenClass):
                token_dict_all = tokenobject.get_as_dict()
                fields = searchRequestDetails.get("fields")
                if fields:
                    token_dict = {}
                    for field in fields:
                        token_dict[field] = token_dict_all[field]
                else:
                    token_dict = token_dict_all

                user_id = token_dict.get("user_id")
                if user_id:
                    token_dict["username"] = user_id

                token_list.append(token_dict)

    ret = {"tokens": token_list,
           "limit": limit,
           "offset": offset,
           "has_next": has_next,
           "count": total_count}
    return ret