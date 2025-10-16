define([
  'uiRegistry'
], function (registry) {
  'use strict';

  // UI registry path to the toolbar buttons container
  var buttonsPath = 'merlin_blocked_ip_listing.' +
                    'merlin_blocked_ip_listing.listing_top.' +
                    'listing_buttons';

  function addButton(buttons) {
    if (!buttons || typeof buttons.insertChild !== 'function') {
      return;
    }

    // If already there, don't duplicate
    if (registry.get(buttonsPath + '.add')) {
      return;
    }

    buttons.insertChild({
      name: 'add',
      component: 'Magento_Ui/js/grid/buttons/button',
      sortOrder: 10,
      displayArea: 'listingToolbar',
      config: {
        label: 'Add Blocked IP',
        class: 'primary',
        // Use controller wildcard so it resolves with secret key automatically
        url: { path: '*/*/new' }
      }
    }, 0);
  }

  // Try immediate get; if not present yet, use async
  var buttons = registry.get(buttonsPath);
  if (buttons) {
    addButton(buttons);
  } else {
    registry.async(buttonsPath)(addButton);
  }
});
