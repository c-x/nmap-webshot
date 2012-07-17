//VERSION 0.2
var width = 1280, height = 1024, timeout = 7000;
var page = new WebPage(), address, output;

if (phantom.args.length != 2) {
    console.log('Usage: screenshot.js URL filename');
    phantom.exit();
} else {
    address = phantom.args[0];
    output = phantom.args[1];
    page.viewportSize = { width: width, height: height };
    // do not cache objects
    page.customHeaders = {"Pragma":"no-cache"}; 
    page.customHeaders = {"Cache-control":"no-cache"}; 

    var address_is_image;
    page.onResourceReceived = function (response) {
        if (response.url == address && response.contentType.match(/^image\/(.+)/)) {
            console.log(address + ' is ' + RegExp.$1);

            address_is_image = 1;
        }
    };

    page.open(address, function (status) {
        if (status !== 'success') {
            console.log('Unable to load the address!');
            console.log('status = ' + status);
            phantom.exit();
        } else {

            if (address_is_image) {
                try {
                    fs.write(output, page.content, "w");
                } catch (e) {
                    console.log(e);
                }
                phantom.exit();
            }

            window.setTimeout(function () {
                page.clipRect = { top: 0, left: 0, width: width, height: height };
                page.evaluate(function() {
                    document.body.bgColor = 'white';
                });
                page.render(output);
                phantom.exit();
            }, timeout);
        }
    });
}
