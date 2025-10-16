define([
  'Magento_Ui/js/form/components/button',
  'jquery'
], function (FormButton, $) {
  'use strict';

  return FormButton.extend({
    defaults: {
      // grid toolbar expects "label"; form button uses "title"
      label: '',
      title: '',
      url: null,

      /** simple template reused from form button */
      template: 'ui/form/components/button/simple',

      // ensure KO sees it
      imports: {
        // if someone sets title from outside, keep label in sync
        title: '${ $.provider }:${ $.dataScope }.title'
      }
    },

    initialize: function () {
      this._super();

      // normalize: if only label provided, mirror into title
      if (this.label && !this.title) {
        this.title = this.label;
      }
      // or if only title provided, mirror into label
      if (this.title && !this.label) {
        this.label = this.title;
      }

      return this;
    },

    /**
     * Override default click behaviour:
     * - if "url" is set -> navigate
     * - else fall back to parent actions
     */
    action: function () {
      if (this.url) {
        window.location.href = this.url;
        return;
      }
      // fallback to original behaviour (actions array, etc.)
      this._super();
    }
  });
});
