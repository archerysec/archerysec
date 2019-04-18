$(document).ready(function() {



    // === Prepare peity charts === //
    maruti.peity();

    // === Prepare the chart data ===/
    var sin = [],
        cos = [];
    for (var i = 0; i < 14; i += 0.5) {
        sin.push([i, Math.sin(i)]);
        cos.push([i, Math.cos(i)]);
    }

    // === Make chart === //
    var plot = $.plot($(".chart"), [{ data: sin, label: "sin(x)", color: "#ee7951" }, { data: cos, label: "cos(x)", color: "#4fb9f0" }], {
        series: {
            lines: { show: true },
            points: { show: true }
        },
        grid: { hoverable: true, clickable: true },
        yaxis: { min: -1.6, max: 1.6 }
    });

    // === Point hover in chart === //
    var previousPoint = null;
    $(".chart").bind("plothover", function(event, pos, item) {

        if (item) {
            if (previousPoint != item.dataIndex) {
                previousPoint = item.dataIndex;

                $('#tooltip').fadeOut(200, function() {
                    $(this).remove();
                });
                var x = item.datapoint[0].toFixed(2),
                    y = item.datapoint[1].toFixed(2);

                maruti.flot_tooltip(item.pageX, item.pageY, item.series.label + " of " + x + " = " + y);
            }

        } else {
            $('#tooltip').fadeOut(200, function() {
                $(this).remove();
            });
            previousPoint = null;
        }
    });
});