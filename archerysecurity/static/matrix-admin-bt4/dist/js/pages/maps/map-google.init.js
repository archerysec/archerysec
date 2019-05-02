/*************************************************************************************/
// -->Template Name: Bootstrap Press Admin
// -->Author: Themedesigner
// -->Email: niravjoshi87@gmail.com
// -->File: google_map_init
/*************************************************************************************/

$(function() {
    //******************************************//
    // Basic Map
    //******************************************//
    var map;
    map = new GMaps({
        div: '#map',
        lat: -12.043333,
        lng: -77.028333
    });

    //******************************************//
    // Map Events
    //******************************************//
    var map_1;
    map_1 = new GMaps({
        div: '#map_1',
        zoom: 16,
        lat: -12.043333,
        lng: -77.028333,
        click: function(e) {
            alert('click');
        },
        dragend: function(e) {
            alert('dragend');
        }
    });

    //******************************************//
    // Markers
    //******************************************//
    var map_2;
    map_2 = new GMaps({
        div: '#map_2',
        lat: -12.043333,
        lng: -77.028333
    });
    map_2.addMarker({
        lat: -12.043333,
        lng: -77.03,
        title: 'Lima',
        details: {
            database_id: 42,
            author: 'HPNeo'
        },
        click: function(e) {
            if (console.log)
                console.log(e);
            alert('You clicked in this marker');
        }
    });
    map_2.addMarker({
        lat: -12.042,
        lng: -77.028333,
        title: 'Marker with InfoWindow',
        infoWindow: {
            content: '<p>HTML Content</p>'
        }
    });

    //******************************************//
    // Polylines
    //******************************************//
    var map_3;
    map_3 = new GMaps({
        div: '#map_3',
        lat: -12.043333,
        lng: -77.028333,
        click: function(e) {
            console.log(e);
        }
    });

    path1 = [
        [-12.044012922866312, -77.02470665341184],
        [-12.05449279282314, -77.03024273281858],
        [-12.055122327623378, -77.03039293652341],
        [-12.075917129727586, -77.02764635449216],
        [-12.07635776902266, -77.02792530422971],
        [-12.076819390363665, -77.02893381481931],
        [-12.088527520066453, -77.0241058385925],
        [-12.090814532191756, -77.02271108990476]
    ];

    map_3.drawPolyline({
        path: path1,
        strokeColor: '#131540',
        strokeOpacity: 0.6,
        strokeWeight: 6
    });

    //******************************************//
    // Polygons
    //******************************************//
    var map_4;
    map_4 = new GMaps({
        div: '#map_4',
        lat: -12.043333,
        lng: -77.028333
    });

    var path2 = [
        [-12.040397656836609, -77.03373871559225],
        [-12.040248585302038, -77.03993927003302],
        [-12.050047116528843, -77.02448169303511],
        [-12.044804866577001, -77.02154422636042]
    ];

    polygon = map_4.drawPolygon({
        paths: path2,
        strokeColor: '#BBD8E9',
        strokeOpacity: 1,
        strokeWeight: 3,
        fillColor: '#BBD8E9',
        fillOpacity: 0.6
    });

    //******************************************//
    // Routes
    //******************************************//
    var map_5;
    map_5 = new GMaps({
        div: '#map_5',
        lat: -12.043333,
        lng: -77.028333
    });
    map_5.drawRoute({
        origin: [-12.044012922866312, -77.02470665341184],
        destination: [-12.090814532191756, -77.02271108990476],
        travelMode: 'driving',
        strokeColor: '#131540',
        strokeOpacity: 0.6,
        strokeWeight: 6
    });

    //******************************************//
    // Routes Advance
    //******************************************//
    var map_6;
    map_6 = new GMaps({
        div: '#map_6',
        lat: -12.043333,
        lng: -77.028333
    });
    $('#start_travel').click(function(e) {
        e.preventDefault();
        map_6.travelRoute({
            origin: [-12.044012922866312, -77.02470665341184],
            destination: [-12.090814532191756, -77.02271108990476],
            travelMode: 'driving',
            step: function(e) {
                $('#instructions').append('<li>' + e.instructions + '</li>');
                $('#instructions li:eq(' + e.step_number + ')').delay(450 * e.step_number).fadeIn(200, function() {
                    map_6.setCenter(e.end_location.lat(), e.end_location.lng());
                    map_6.drawPolyline({
                        path: e.path,
                        strokeColor: '#131540',
                        strokeOpacity: 0.6,
                        strokeWeight: 6
                    });
                });
            }
        });
    });

    //******************************************//
    // Street View Panoramas
    //******************************************//
    panorama = GMaps.createPanorama({
        el: '#panorama',
        lat: 42.3455,
        lng: -71.0983
    });

    //******************************************//
    // Map Types
    //******************************************//
    var map_7;
    map_7 = new GMaps({
        div: '#map_7',
        lat: -12.043333,
        lng: -77.028333,
        mapTypeControlOptions: {
            mapTypeIds: ["hybrid", "roadmap", "satellite", "terrain", "osm"]
        }
    });
    map_7.addMapType("osm", {
        getTileUrl: function(coord, zoom) {
            return "https://a.tile.openstreetmap.org/" + zoom + "/" + coord.x + "/" + coord.y + ".png";
        },
        tileSize: new google.maps.Size(256, 256),
        name: "OpenStreetMap",
        maxZoom: 18
    });
    map_7.setMapTypeId("osm");

    //******************************************//
    // Fusion Tables layers
    //******************************************//
    var map_8, infoWindow1;
    infoWindow = new google.maps.InfoWindow({});
    map_8 = new GMaps({
        div: '#map_8',
        zoom: 11,
        lat: 41.850033,
        lng: -87.6500523
    });
    map_8.loadFromFusionTables({
        query: {
            select: '\'Geocodable address\'',
            from: '1mZ53Z70NsChnBMm-qEYmSDOvLXgrreLTkQUvvg'
        },
        suppressInfoWindows: true,
        events: {
            click: function(point) {
                infoWindow.setContent('You clicked here!');
                infoWindow.setPosition(point.latLng);
                infoWindow.open(map_8.map_8);
            }
        }
    });

    //******************************************//
    // KML layers
    //******************************************//
    var map_9, infoWindow2;
    infoWindow2 = new google.maps.InfoWindow({});
    map_9 = new GMaps({
        div: '#map_9',
        zoom: 12,
        lat: 40.65,
        lng: -73.95
    });
    map_9.loadFromKML({
        url: 'http://api.flickr.com/services/feeds/geo/?g=322338@N20&lang=en-us&format=feed-georss',
        suppressInfoWindows: true,
        events: {
            click: function(point) {
                infoWindow2.setContent(point.featureData.infoWindowHtml);
                infoWindow2.setPosition(point.latLng);
                infoWindow2.open(map_9.map_9);
            }
        }
    });

    //******************************************//
    // Geofences
    //******************************************//
    var map_10;
    map_10 = new GMaps({
        div: '#map_10',
        lat: -12.043333,
        lng: -77.028333
    });
    var path3 = [];
    var p = [
        [-12.040397656836609, -77.03373871559225],
        [-12.040248585302038, -77.03993927003302],
        [-12.050047116528843, -77.02448169303511],
        [-12.044804866577001, -77.02154422636042]
    ];
    for (var i in p) {
        latlng = new google.maps.LatLng(p[i][0], p[i][1]);
        path3.push(latlng);
    }
    polygon = map_10.drawPolygon({
        paths: path3,
        strokeColor: '#BBD8E9',
        strokeOpacity: 1,
        strokeWeight: 3,
        fillColor: '#BBD8E9',
        fillOpacity: 0.6
    });
    map_10.addMarker({
        lat: -12.043333,
        lng: -77.028333,
        draggable: true,
        fences: [polygon],
        outside: function(m, f) {
            alert('This marker has been moved outside of its fence');
        }
    });
});