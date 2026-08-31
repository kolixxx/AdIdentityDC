<script>
    $(document).ready(function () {
        mapDataToFormUI({
            '#frm_general_settings': "/api/adidentity/settings/get"
        }).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function () {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/adidentity/settings/set", 'frm_general_settings', function () {
                    dfObj.resolve();
                }, true, function () {
                    dfObj.reject();
                });
                return dfObj;
            }
        });

        $("#resyncAct").SimpleActionButton();
    });
</script>

<div class="content-box">
    <div class="table-responsive">
        {{ partial("layout_partials/base_form",['fields':generalForm,'id':'frm_general_settings']) }}
    </div>
    <div class="col-md-12 __mt">
        <button class="btn btn-primary" id="reconfigureAct"
                data-endpoint="/api/adidentity/service/reconfigure"
                data-label="{{ lang._('Apply') }}"
                data-error-title="{{ lang._('Error reconfiguring AdIdentity') }}"
                type="button">
        </button>
        <button class="btn btn-default" id="resyncAct"
                data-endpoint="/api/adidentity/service/resync"
                data-label="{{ lang._('Resync from Agent') }}"
                data-error-title="{{ lang._('Error resyncing from Agent') }}"
                type="button">
        </button>
    </div>
</div>

<div class="content-box __mt">
    <div class="col-md-12">
        <h2>{{ lang._('Pilot notes') }}</h2>
        <ul>
            <li>{{ lang._('Agent pushes login sessions; Plugin updates External aliases.') }}</li>
            <li>{{ lang._('Admin writes Firewall Rules using those aliases.') }}</li>
            <li>{{ lang._('Apply also attempts Plugin <- Agent resync. Use Resync manually anytime.') }}</li>
        </ul>
    </div>
</div>
