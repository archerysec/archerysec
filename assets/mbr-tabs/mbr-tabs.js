$.fn.outerFind = function(selector) {
    return this.find(selector).addBack(selector);
};
function initTabs(target) {
    if ($(target).find('.nav-tabs').length !== 0) {
        $(target).outerFind('section[id^="tabs"]').each(function() {
            var componentID = $(this).attr('id');
            var $tabsNavItem = $(this).find('.nav-tabs .nav-item');
            var $tabPane = $(this).find('.tab-pane');

            $tabPane.removeClass('active').eq(0).addClass('active');

            $tabsNavItem.find('a').removeClass('active').removeAttr('aria-expanded')
                .eq(0).addClass('active');

            $tabPane.each(function() {
                $(this).attr('id', componentID + '_tab' + $(this).index());
            });

            $tabsNavItem.each(function() {
                $(this).find('a').attr('href', '#' + componentID + '_tab' + $(this).index());
            });
        });
    }
}

// Mobirise Initilizaton
var isBuilder = $('html').hasClass('is-builder');
if (isBuilder) {
    $(document).on('add.cards', function(e) {
        initTabs(e.target);
    });
} else {
    if (typeof window.initTabsPlugin === 'undefined'){
        window.initTabsPlugin = true;
        console.log('init tabs by plugin');
        initTabs(document.body);
    }
}