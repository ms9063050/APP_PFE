const input = document.querySelector('#input_file');

// Listen for files selection
input.addEventListener('change', (e) => {
    // Retrieve all files
    const files = input.files;

    // Check files count
    if (files.length > 2) {
        alert("Only 2 files are allowed to upload.");
        return;
    }

    // TODO: continue uploading on server
});




$(document).ready(function(){
    $("a[href='#header']").on("click", function (e) {
            $("html, body").animate({
                scrollTop: $($(this).attr("href")).offset().top /* scroll to the matching id */
            }, 1000); /* here 1000 in ms */
     });
    });