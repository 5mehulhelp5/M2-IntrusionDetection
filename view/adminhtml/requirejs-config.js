var config = {
    map: {
        '*': {
            // Map moment to prevent map file errors
            'moment': 'moment'
        }
    },
    config: {
        mixins: {
            'Magento_Ui/js/form/provider': {
                'Merlin_IntrusionDetection/js/form/provider-mixin': false
            }
        }
    }
};
