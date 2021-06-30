import { API } from '../../js/api.js';
import { PAGES } from '../../js/contants.js';

(function ($) {
    "use strict";

    $('#successful-authentications-link').on('click', e => {
        e.preventDefault();

        $('#successful-authentications-table').css('display', '');
        $('#failed-authentications-table').css('display', 'none');
        $('#active-sessions-table').css('display', 'none');
    });

    $('#failed-authentications-link').on('click', e => {
        e.preventDefault();

        $('#successful-authentications-table').css('display', 'none');
        $('#failed-authentications-table').css('display', '');
        $('#active-sessions-table').css('display', 'none');
    });

    $('#active-sessions-link').on('click', e => {
        e.preventDefault();

        $('#successful-authentications-table').css('display', 'none');
        $('#failed-authentications-table').css('display', 'none');
        $('#active-sessions-table').css('display', '');
    });

    $('#logout-link').on('click', e => {
        e.preventDefault();

        API.logout()
            .then(() => {
                window.location.href = PAGES.LOGIN;
            })
            .catch(e => {
                toastr.error(e.message, e.code || 'Error');
            });
    });

    $('#logout-all-link').on('click', e => {
        e.preventDefault();

        API.logoutAll()
            .then((response) => {
                toastr.success(`Logged out from ${response.numberOfDeletedSessions} sessions.`);
                setTimeout(() => {
                    window.location.href = PAGES.LOGIN;
                }, 2000);
            })
            .catch(e => {
                toastr.error(e.message, e.code || 'Error');
            });
    });

})(jQuery);
