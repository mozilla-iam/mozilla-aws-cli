// we fire on load, as that means all the images, fonts, etc. are loaded
window.addEventListener("load", () => {
   const url = new URL(document.location);

   // make a fetch request
   fetch("/redirect_callback", {
       method: "POST",
       body: JSON.stringify({
           code: url.searchParams.get("code"),
           state: url.searchParams.get("state"),
           error: url.searchParams.get("error"),
           error_description: url.searchParams.get("error_description"),
       }),
       headers: {
           "Content-Type": "application/json",
       },
   }).then((response) => {
       console.log("Successfully posted with", response);
   }).catch((error) => {
       console.error("Unable to POST to callback", error);
   });
});
