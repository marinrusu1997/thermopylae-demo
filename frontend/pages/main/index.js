import { API } from '../../js/api.js';
import { PAGES } from '../../js/contants.js';
import { ApiError } from "../../js/api-error.js";

(function ($) {
    "use strict";

    $('#successful-authentications-link').on('click', e => {
        e.preventDefault();

        API.getSuccessfulAuthentications()
            .then(authentications => {
                const successfulAuthenticationsTable = $('#successful-authentications-table');
                const successfulAuthenticationsTableBody = successfulAuthenticationsTable.find('tbody');

                successfulAuthenticationsTableBody.empty();

                for (let i = 0; i < authentications.length; i++) {
                    successfulAuthenticationsTableBody.append(
                        $('<tr>')
                            .append($('<th>').attr('scope', 'row').text(String(i + 1)))
                            .append($('<th>').text(authentications[i].ip))
                            .append($('<td>').text(JSON.stringify(authentications[i].device)))
                            .append($('<td>').text(JSON.stringify(authentications[i].location)))
                            .append($('<td>').text(new Date(authentications[i].authenticatedAt * 1000).toISOString()))
                    );
                }

                successfulAuthenticationsTable.css('display', '');
                $('#failed-authentications-table').css('display', 'none');
                $('#active-sessions-table').css('display', 'none');
            }).catch(handleApiError);
    });

    $('#failed-authentications-link').on('click', e => {
        e.preventDefault();

        API.getFailedAuthentications()
            .then(authentications => {
                const failedAuthenticationsTable = $('#failed-authentications-table');
                const failedAuthenticationsTableBody = failedAuthenticationsTable.find('tbody');

                failedAuthenticationsTableBody.empty();

                for (let i = 0; i < authentications.length; i++) {
                    failedAuthenticationsTableBody.append(
                        $('<tr>')
                            .append($('<th>').attr('scope', 'row').text(String(i + 1)))
                            .append($('<th>').text(authentications[i].ip))
                            .append($('<td>').text(JSON.stringify(authentications[i].device)))
                            .append($('<td>').text(JSON.stringify(authentications[i].location)))
                            .append($('<td>').text(new Date(authentications[i].detectedAt * 1000).toISOString()))
                    );
                }

                $('#successful-authentications-table').css('display', 'none');
                failedAuthenticationsTable.css('display', '');
                $('#active-sessions-table').css('display', 'none');
            }).catch(handleApiError);
    });

    $('#active-sessions-link').on('click', e => {
        e.preventDefault();

        API.getActiveSessions()
            .then(sessions => {
                const activeSessionsTable = $("#active-sessions-table");
                const activeSessionsTableBody = activeSessionsTable.find('tbody');

                activeSessionsTableBody.empty();
                for (const [/** @type {string} */ refreshToken, /** @type {UserSessionMetaData} */ session] of Object.entries(sessions)) {
                    const tableRow = $('<tr>')
                        .append($('<th>').attr('scope', 'row').text(session.ip))
                        .append($('<td>').text(JSON.stringify(session.device)))
                        .append($('<td>').text(JSON.stringify(session.location)))
                        .append($('<td>').text(new Date(session.createdAt * 1000).toISOString()))
                        .append($('<td>').text(new Date(session.expiresAt * 1000).toISOString()))
                        .append($('<td>').append(
                            $('<button>')
                                .attr('type', 'button')
                                .attr('class', 'btn btn-danger btn-sm px-3')
                                .append(
                                    $('<i>').attr('class', 'fas fa-times')
                                )
                                .on('click', e => {
                                    e.preventDefault();

                                    API.logoutOne(refreshToken)
                                        .then(() => {
                                            toastr.success('Session logged out');
                                            tableRow.remove();
                                        }).catch(handleApiError);
                                })
                        ));

                    activeSessionsTableBody.append(tableRow);
                }

                activeSessionsTable.css('display', '');
                $('#successful-authentications-table').css('display', 'none');
                $('#failed-authentications-table').css('display', 'none');
            })
            .catch(handleApiError);
    });

    $('#change-password-link').on('click', e => {
        e.preventDefault();
        $('#change-password-modal').modal('toggle');
    });
    $('#change-password-modal-btn').on('click', () => {
        /* GET VALUES */
        const oldPassword = $('#change-password-old-password-input').val().trim();
        const newPassword = $('#change-password-new-password-input').val().trim();
        const confirmPassword = $('#change-password-new-password-confirm-input').val().trim();

        /* VALIDATE THEM */
        if (!oldPassword) {
            return toastr.warning('Please enter old password');
        }
        if (oldPassword.length < 14) {
            return toastr.warning('Old password needs to contain at least 14 characters');
        }
        if (oldPassword.length > 4096) {
            return toastr.warning('Old password needs to contain no more than 4096 characters');
        }

        if (!newPassword) {
            return toastr.warning('Please enter new password');
        }
        if (newPassword.length < 14) {
            return toastr.warning('New password needs to contain at least 14 characters');
        }
        if (newPassword.length > 4096) {
            return toastr.warning('New password needs to contain no more than 4096 characters');
        }

        if (!confirmPassword) {
            return toastr.warning('Please enter new password confirmation');
        }
        if (newPassword !== confirmPassword) {
            return toastr.warning('Confirmed password does not match new password');
        }

        /* CHANGE PASSWORD */
        runWaitMe('change-password-form');
        API.changePassword(oldPassword, newPassword)
            .then(() => {
                toastr.success('Password has been changed.');
                $('#change-password-modal').modal('hide');

                setTimeout(() => {
                    window.location.href = PAGES.LOGIN;
                }, 1000);
            })
            .catch(handleApiError)
            .finally(() => stopWaitMe('change-password-form'));
    });

    $('#two-factor-link').on('click', e => {
        e.preventDefault();
        $('#qr-code-container').empty();
        $('#two-factor-modal').modal('toggle');
    });
    $('#two-factor-modal-btn').on('click', () => {
        /* GET VALUES */
        const password = $('#two-factor-password-input').val().trim();
        const enabled = $('#two-factor-enable-input').prop('checked');

        /* VALIDATE THEM */
        if (!password) {
            return toastr.warning('Please enter password');
        }
        if (password.length < 14) {
            return toastr.warning('Password needs to contain at least 14 characters');
        }
        if (password.length > 4096) {
            return toastr.warning('Password needs to contain no more than 4096 characters');
        }

        /* SET 2FA */
        runWaitMe('two-factor-form');
        API.setTwoFactorAuth(password, enabled)
            .then((result) => {
                toastr.success(enabled ? 'Two factor authentication has been enabled.' : 'Two factor authentication has been disabled.');

                if (!result) {
                    $('#change-password-modal').modal('hide');
                    return;
                }

                $('#qr-code-container').append(
                    $('<p>').text('Scan the following QR code with the Google Authenticator app from your mobile phone.')
                );
                $('#qr-code-container').append(
                    $('<center>').append(
                        $('<img>').attr('src', result.totpSecretQRImageUrl)
                    )
                );
            })
            .catch(handleApiError)
            .finally(() => stopWaitMe('two-factor-form'));
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
                }, 1000);
            })
            .catch(e => {
                toastr.error(e.message, e.code || 'Error');
            });
    });

    /* UTILS */
    function runWaitMe(formId) {
        $(`#${formId}`).waitMe({
            effect: 'roundBounce',
            text: '',
            bg: 'rgba(255,255,255,0.7)',
            color: '#000',
            waitTime: -1
        });
    }

    function stopWaitMe(formId) {
        $(`#${formId}`).waitMe('hide');
    }

    function handleApiError(e) {
        toastr.error(e.message, e.code || 'Error');

        if (e instanceof ApiError && e.code === 'INVALID_SESSION') {
            setTimeout(() => {
                window.location.href = PAGES.LOGIN;
            }, 1000);
        }
    }

})(jQuery);
