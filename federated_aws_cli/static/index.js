const setMessage = (message) => {
    document.getElementById("message").innerText = message;
};

// we fire on load, as that means all the images, fonts, etc. are loaded
window.addEventListener("load", async () => {
   const url = new URL(document.location);

   // make a fetch request
   r = fetch("/redirect_callback", {
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
   }).then(async (response) => {
       data = await response.json();

       console.log("Successfully POSTed to callback", data);

       // we received a redirect, so shutdown and then redirect
       if (data.result === "redirect") {
           console.log("Attempting to shutdown Flask listener");

           setMessage("Redirecting to AWS, please hold.");

           // shutdown the listener
           fetch("/shutdown", {
               method: "GET",
               cache: "no-cache"
           }).then(() => {
               console.log("Successfully shutdown Flask listener, redirecting...");
               document.location = data.url;
           });
       } else {
           setMessage("You may now close this window.")
       }
   }).catch((error) => {
       console.error("Unable to POST to callback", error);
       setMessage("You may now close this window.")
   });
});
