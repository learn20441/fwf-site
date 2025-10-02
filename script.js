// Membership form submit
if (document.getElementById('membershipForm')) {
  document.getElementById('membershipForm').onsubmit = function(e) {
    e.preventDefault();
    document.getElementById('response').innerText = "Thank you for joining! We will contact you soon.";
  };
}

// Donate form submit
if (document.getElementById('donateForm')) {
  document.getElementById('donateForm').onsubmit = function(e) {
    e.preventDefault();
    document.getElementById('thankyou').innerText = "Thank you for your support!";
  };
}

// Corporate partnership form
if (document.getElementById('partnerForm')) {
  document.getElementById('partnerForm').onsubmit = function(e) {
    e.preventDefault();
    document.getElementById('partnerResponse').innerText = "Thank you! Our team will reach out to discuss the partnership.";
  };
}

// Contact form
if (document.getElementById('contactForm')) {
  document.getElementById('contactForm').onsubmit = function(e) {
    e.preventDefault();
    document.getElementById('contactResponse').innerText = "Thank you! We will respond soon.";
  };
}

// Project interest registration (for ALL buttons with .register-interest class)
document.querySelectorAll('.register-interest').forEach(function(btn) {
  btn.addEventListener('click', function() {
    alert("Training details will be sent to your email.");
  });
});

// Homepage impact counters (optional)
// Add counters only if elements exist and you want numbers animation
function animateCounter(id, start, end, speed) {
  var el = document.getElementById(id);
  if (!el) return;
  let current = start;
  let interval = setInterval(function() {
    el.innerText = current;
    current++;
    if (current > end) clearInterval(interval);
  }, speed);
}
// Example: animateCounter("counter1", 3100, 3500, 10);
// Example use in Home page: <span id="counter1"></span>

// Navbar highlight (basic demo)
document.querySelectorAll('nav a').forEach(function(link) {
  if (window.location.pathname.includes(link.getAttribute('href'))) {
    link.style.background = '#48cae4';
    link.style.color = '#0077b6';
  }
});
