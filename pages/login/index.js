import { CORE_VALIDATOR } from '../../js/validators.js';
import { API } from '../../js/api.js';
import { PAGES, SYMBOLS } from '../../js/contants.js';

(function ($) {
    "use strict";


     /*==================================================================
    [ Focus input ]*/
    $('.input100').each(function () {
        $(this).on('blur', function () {
            if ($(this).val().trim() !== "") {
                $(this).addClass('has-val');
            }
            else {
                $(this).removeClass('has-val');
            }
        })
    })

    /*==================================================================
    [ Attach navigation ]*/
    $($('#forgot-password-link')[0]).attr('href', PAGES.FORGOT_PASSWORD);
    $($('#register-link')[0]).attr('href', PAGES.REGISTER);


    /*==================================================================
    [ Validate ]*/
    /**
     * @type {Map<string, *|define.amd.jQuery|HTMLElement>}
     */
    const inputs = new Map();

    const jqueryInputs = $('.validate-input .input100');
    for (let i = 0; i < jqueryInputs.length; i++) {
        inputs.set($(jqueryInputs[i]).attr('name'), jqueryInputs[i]);
    }

    /** @type {boolean} */
    let recaptchaRequired = false;
    /** @type {boolean} */
    let totpRequired = false;

    $('.validate-form').on('submit', function (evt) {
        evt.preventDefault();

        let check = true;
        let errMsg;

        for (const [name, input] of inputs) {
            errMsg = validate(name, input);
            if (errMsg != null) {
                showValidate(input, errMsg);
                check = false;
            }
        }

        if (check) {
            if (recaptchaRequired && window[SYMBOLS.WINDOW_RECAPTCHA_TOKEN] == null) {
                toastr.error('Recaptcha token is not available yet.', 'Error');
                return false;
            }

            runWaitMe();

            API.authenticate({
                username: $(inputs.get('username')).val().trim(),
                password: $(inputs.get('password')).val().trim(),
                recaptcha: recaptchaRequired ? window[SYMBOLS.WINDOW_RECAPTCHA_TOKEN] : undefined,
                "2fa-token": totpRequired ? $(inputs.get('totp')).val().trim() : undefined
            }).then((authenticationStatus) => {
                recaptchaRequired = false;

                if (authenticationStatus.account) {
                    window.location.href = PAGES.MAIN;
                    return;
                }

                if (authenticationStatus.error) {
                    if (authenticationStatus.nextStep) {
                        if (authenticationStatus.nextStep === 'PASSWORD') {
                            toastr.error('Username/Password are not correct.', 'Error');
                            return;
                        }

                        if (authenticationStatus.nextStep === 'RECAPTCHA') {
                            if (authenticationStatus.error.code === 'INCORRECT_CREDENTIALS') {
                                toastr.error('Username/Password are not correct.', 'Error');
                            }
                            if (authenticationStatus.error.code === 'INCORRECT_RECAPTCHA') {
                                toastr.error('Recaptcha has low score.', 'Error');
                            }

                            recaptchaRequired = true;
                            return;
                        }

                        if (authenticationStatus.nextStep === 'TWO_FACTOR_AUTH_CHECK') {
                            toastr.error('TOTP is not correct.', 'Error');

                            totpRequired = true;
                            return;
                        }
                    }

                    if (authenticationStatus.error.code === 'INVALID_INPUT') {
                        toastr.error(authenticationStatus.error.message, 'Error');
                        return;
                    }

                    if (authenticationStatus.error.code === 'TOO_MANY_SESSIONS') {
                        toastr.error(authenticationStatus.error.message, authenticationStatus.error.code);
                        return;
                    }

                    if (authenticationStatus.error.code === 'ACCOUNT_DISABLED') {
                        toastr.error('Account is disabled.', 'Error');
                        return;
                    }

                    if (authenticationStatus.error.code === 'INCORRECT_CREDENTIALS') {
                        toastr.error('Username/Password are not correct.', 'Error');
                        return;
                    }

                    if (authenticationStatus.error.code === 'TWO_FACTOR_AUTH_TOKEN_ISSUED_ALREADY') {
                        toastr.error('Two factor authentication code was issued already.', 'Error');
                        return;
                    }
                }

                if (authenticationStatus.nextStep) {
                    if (authenticationStatus.nextStep === 'TWO_FACTOR_AUTH_CHECK') {
                        toastr.warning('Provide totp from authenticator app.')
                        $('#totp-form-div')[0].removeAttr('hidden');
                        totpRequired = true;
                    }
                }

                throw new Error(`Unable to handle authentication status: ${JSON.stringify(authenticationStatus)}.`);
            }).catch(err => {
                toastr.error(err.message, err.code || 'Error');
            }).finally(stopWaitMe);
        }

        return check;
    });


    $('.validate-form .input100').each(function () {
        $(this).focus(function () {
           hideValidate(this);
        });
    });

    function runWaitMe() {
        $('#authentication_form').waitMe({
            effect: 'roundBounce',
            text: '',
            bg: 'rgba(255,255,255,0.7)',
            color: '#000',
            waitTime: -1
        });
    }

    function stopWaitMe() {
        $('#authentication_form').waitMe('hide');
    }

    function validate (name, input) {
        if (name === 'username') {
            return CORE_VALIDATOR.USERNAME($(input).val().trim());
        }

        if (name === 'password') {
            return CORE_VALIDATOR.PASSWORD($(input).val().trim());
        }

        if (name === 'totp') {
            if ($($('#totp-form-div')[0]).attr('hidden') === 'hidden') {
                return null;
            }

            return CORE_VALIDATOR.TOTP($(input).val().trim());
        }

        throw new Error('Unknown input');
    }

    function showValidate(input, errMsg) {
        let thisAlert = $(input).parent();

        $(thisAlert).addClass('alert-validate');
        $(thisAlert).attr('data-validate', errMsg);
    }

    function hideValidate(input) {
        let thisAlert = $(input).parent();

        $(thisAlert).removeClass('alert-validate');
        $(thisAlert).attr('data-validate', '');
    }



})(jQuery);
