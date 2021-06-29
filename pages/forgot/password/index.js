import { API } from '../../../js/api.js';
import { PAGES } from '../../../js/contants.js';
import { CRYPTO } from '../../../js/crypto.js';

(function ($) {
    "use strict";

    /* FORM VALIDATION */
    jQuery.validator.setDefaults({
        success: function (label) {
            label.attr('id', 'valid');
        },
    });

    $("#request-forgot-password-token-form").validate({
        submitHandler: function (form, event) {
            event.preventDefault();

            const fieldName = $('#remembered-field-name').select2('data')[0].text;
            const fieldValue = $('#remembered-field-value').val().trim();

            runWaitMe('request-forgot-password-token-form');
            API.createForgotPasswordSession(fieldName, fieldValue)
                .then(() => {
                    toastr.success('Forgot password token has been sent.');
                    $('#resetPasswordModal').modal('toggle');
                }).catch(e => {
                    toastr.error(e.message, e.code || 'Error');
                }).finally(() => stopWaitMe('request-forgot-password-token-form'));
        }
    });

    $('#reset-password-modal-btn').on('click', async () => {
        /* GET VALUES */
        let token = $('#reset-password-token-input').val().trim();
        const newPassword = $('#reset-password-new-password-input').val().trim();
        const confirmPassword = $('#reset-password-new-password-confirm-input').val().trim();
        const privateKey = $('#reset-password-private-key-input').val().trim();

        /* VALIDATE THEM */
        if (!token) {
            return toastr.warning('Please enter reset password token');
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

        /* DECRYPT TOKEN */
        if (privateKey) {
            try {
                token = CRYPTO.privateDecrypt(privateKey, token);
            } catch (e) {
                toastr.error(e.message, 'INVALID PRIVATE KEY');
                return;
            }
        }

        /* CHANGE PASSWORD */
        runWaitMe('reset-password-form');
        API.changeForgottenPassword(token, newPassword)
            .then(() => {
                toastr.success('Password has been reset.');
                $('#resetPasswordModal').modal('hide');

                setTimeout(() => {
                    window.location.href = PAGES.LOGIN;
                }, 2000);
            }).catch(e => {
                toastr.error(e.message, e.code || 'Error');
            }).finally(() => stopWaitMe('reset-password-form'));
    });

    /* LISTENERS */
    $('#back-to-login-btn').on('click', () => {
       window.location.href = PAGES.LOGIN;
    });

    /* SELECT OPTION */
    $('#remembered-field-name').select2({
        placeholder: 'Please select a field',
        theme: "classic",
        selectOnClose: true
    });

    $('#remembered-field-name').on('select2:select', function (e) {
        switch (e.params.data.id) {
            case 'USR':
                $('#remembered-field-value-label').text("Enter account username");
                $('#remembered-field-value-details').text('Enter the username you used during the account registration. Then we\'ll email a token to account email address.');
                $('#remembered-field-value').attr('pattern', '^(?=.{6,50}$)(?![_.])(?!.*[_.]{2})[a-zA-Z0-9._]+(?<![_.])$');
                break;

            case 'EML':
                $('#remembered-field-value-label').text("Enter account email");
                $('#remembered-field-value-details').text('Enter the email address you used during the account registration. Then we\'ll email a token to this address.');
                $('#remembered-field-value').attr('pattern', '^(([^<>()[\\]\\\\.,;:\\s@\\"]+(\\.[^<>()[\\]\\\\.,;:\\s@\\"]+)*)|(\\".+\\"))@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\])|(([a-zA-Z\\-0-9]+\\.)+[a-zA-Z]{2,}))$');
                break;

            case 'TEL':
                $('#remembered-field-value-label').text("Enter account telephone");
                $('#remembered-field-value-details').text('Enter the telephone number you used during the account registration. Then we\'ll send a sms with token to that number.');
                $('#remembered-field-value').attr('pattern', '^\\+[1-9]\\d{1,14}$');
                break;

            default:
                console.error('Unknown selection ' + e.params.data.id);
        }
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
})(jQuery);
