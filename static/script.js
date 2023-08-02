'use strict';

window.addEventListener('load', function () {

  console.log("Hello World!");

});

// Wait for the document to be ready
document.addEventListener('DOMContentLoaded', function() {
  // Get the pop-up button and pop-up element
  var popupBtn = document.querySelector('.popup-btn');
  var popup = document.querySelector('.popup');

  // Add click event listener to the pop-up button
  popupBtn.addEventListener('click', function() {
    // Display the pop-up element
    popup.style.display = 'block';
  });

  // Get the close button inside the pop-up element
  var closeBtns = document.querySelectorAll('.close-btn');

  // Add click event listener to each close button
  closeBtns.forEach(function(closeBtn) {
    closeBtn.addEventListener('click', function() {
      // Hide the pop-up element
      popup.style.display = 'none';
    });
  });
});