<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true displayRequiredFields=false; section>
    <#if section = "header">
        ${msg("irc-ecdsa-enroll-title")}
    <#elseif section = "form">
        <form id="kc-irc-ecdsa-enroll-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <label for="publicKey" class="${properties.kcLabelClass!}">${msg("irc-ecdsa-public-key")}</label>
                <div class="${properties.kcInputClass!}">
                    <textarea id="publicKey" name="publicKey" rows="6" required autocomplete="off" spellcheck="false"></textarea>
                </div>
                <p>${msg("irc-ecdsa-enroll-help")}</p>
            </div>
            <div class="${properties.kcFormGroupClass!}">
                <input type="submit" id="kc-submit" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}" value="${msg("doSubmit")}"/>
                <#if isAppInitiatedAction??>
                    <button type="submit" id="kc-cancel" class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} ${properties.kcButtonDefaultClass!}" name="cancel-aia" value="true">${msg("doCancel")}</button>
                </#if>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
