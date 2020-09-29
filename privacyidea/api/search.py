from flask import (Blueprint, request, g, current_app)
from ..lib.search import get_tokens_paginate_no_ldap, get_search_groups_paginate_no_ldap
from ..lib.log import log_with
from .lib.utils import optional, send_result, send_csv_result, required, getParam
from ..lib.user import get_user_from_param
from ..lib.token import (init_token, get_tokens_paginate, assign_token,
                         unassign_token, remove_token, enable_token,
                         revoke_token,
                         reset_token, resync_token, set_pin_so, set_pin_user,
                         set_pin, set_description, set_count_window,
                         set_sync_window, set_count_auth,
                         set_hashlib, set_max_failcount, set_realms,
                         copy_token_user, copy_token_pin, lost_token,
                         get_serial_by_otp, get_tokens,
                         set_validity_period_end, set_validity_period_start, add_tokeninfo,
                         delete_tokeninfo, import_token)
from ..lib.search import get_tokens_paginate_no_ldap           
from werkzeug.datastructures import FileStorage
from cgi import FieldStorage
from privacyidea.lib.error import (ParameterError, TokenAdminError)
from privacyidea.lib.importotp import (parseOATHcsv, parseSafeNetXML,
                                       parseYubicoCSV, parsePSKCdata, GPGImport)
import logging
from privacyidea.lib.utils import to_unicode
from privacyidea.lib.policy import ACTION
from privacyidea.lib.challenge import get_challenges_paginate
from privacyidea.api.lib.prepolicy import (prepolicy, check_base_action,
                                           check_token_init, check_token_upload,
                                           check_max_token_user,
                                           check_max_token_realm,
                                           init_tokenlabel, init_random_pin,
                                           encrypt_pin, check_otp_pin,
                                           check_external, init_token_defaults,
                                           enroll_pin, papertoken_count,
                                           tantoken_count,
                                           u2ftoken_allowed, u2ftoken_verify_cert,
                                           twostep_enrollment_activation,
                                           twostep_enrollment_parameters,
                                           sms_identifiers, pushtoken_add_config,
                                           check_admin_tokenlist)
from privacyidea.api.lib.postpolicy import (save_pin_change,
                                            postpolicy)
from privacyidea.lib.event import event
from privacyidea.api.auth import admin_required
from privacyidea.lib.subscriptions import CheckSubscription

search_blueprint = Blueprint('search_blueprint', __name__)
log = logging.getLogger(__name__)

@search_blueprint.route('/', methods=['GET'])
@prepolicy(check_admin_tokenlist, request)
@event("token_list", request, g)
@log_with(log)
def list_api():
    param = request.all_data
    user = request.User
    serial = getParam(param, "serial", optional)
    page = int(getParam(param, "page", optional, default=1))
    tokentype = getParam(param, "type", optional)
    description = getParam(param, "description", optional)
    sort = getParam(param, "sortby", optional, default="serial")
    sdir = getParam(param, "sortdir", optional, default="asc")
    psize = int(getParam(param, "pagesize", optional, default=15))
    realm = getParam(param, "tokenrealm", optional)
    userid = getParam(param, "userid", optional)
    resolver = getParam(param, "resolver", optional)
    ufields = getParam(param, "user_fields", optional)
    output_format = getParam(param, "outform", optional)
    assigned = getParam(param, "assigned", optional)
    active = getParam(param, "active", optional)
    revoked = getParam(param, "revoked", optional)
    locked = getParam(param, "locked", optional)
    deviceType = getParam(param, "deviceType", optional)
    deviceSerial = getParam(param, "deviceSerial", optional)
    validity_period_end_from = getParam(param, "validity_period_end_from", optional)
    validity_period_end_to = getParam(param, "validity_period_end_to", optional)
    validity_period_start_from = getParam(param, "validity_period_start_from", optional)
    validity_period_start_to = getParam(param, "validity_period_start_to", optional)

    if assigned:
        assigned = assigned.lower() == "true"
    if active:
        active = active.lower() == "true"
    if revoked:
        revoked = revoked.lower() == "true"
    if locked:
        locked = locked.lower() == "true"
    
    user_fields = []
    if ufields:
        user_fields = [u.strip() for u in ufields.split(",")]

    # allowed_realms determines, which realms the admin would be allowed to see
    # In certain cases like for users, we do not have allowed_realms
    allowed_realms = getattr(request, "pi_allowed_realms", None)
    g.audit_object.log({'info': "realm: {0!s}".format((allowed_realms))})

    # get list of tokens as a dictionary
    tokens = get_tokens_paginate_no_ldap(serial=serial, realm=realm, page=page,
                                 user=user, assigned=assigned, psize=psize,
                                 sortby=sort, sortdir=sdir,
                                 tokentype=tokentype,
                                 resolver=resolver,
                                 description=description,
                                 userid=userid, allowed_realms=allowed_realms,
                                 active=active, revoked=revoked, locked=locked,
                                 deviceType=deviceType, deviceSerial=deviceSerial,
                                 validity_period_end_from=validity_period_end_from,
                                 validity_period_end_to=validity_period_end_to,
                                 validity_period_start_from=validity_period_start_from,
                                 validity_period_start_to=validity_period_start_to)
    g.audit_object.log({"success": True})
    if output_format == "csv":
        return send_csv_result(tokens)
    return send_result(tokens)

@search_blueprint.route('/', methods=['POST'])
@prepolicy(check_admin_tokenlist, request)
@event("token_list", request, g)
@log_with(log)
def post_list_api():
    param = request.all_data
    searchRequestDetails = getParam(param, "searchRequestDetails", optional)

    allowed_realms = getattr(request, "pi_allowed_realms", None)
    g.audit_object.log({'info': "realm: {0!s}".format((allowed_realms))})

    if searchRequestDetails:
        tokens = get_search_groups_paginate_no_ldap(searchRequestDetails=searchRequestDetails)

    g.audit_object.log({"success": True})
    return send_result(tokens)