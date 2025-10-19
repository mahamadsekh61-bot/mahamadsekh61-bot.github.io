/**
 * PHOENIX PROTOCOL - HACKER MATRIX BACKGROUND ANIMATION
 * Constitutional Authority: Creative Guild + Engineering Guild
 * Purpose: Dynamic particle network visualization for "live, intelligent AI" brand identity
 * Version: 1.0 (October 2025)
 */

particlesJS('particles-js', {
  "particles": {
    "number": {
      "value": 150,              // Dense but not overcrowded constellation
      "density": {
        "enable": true,
        "value_area": 800
      }
    },
    "color": {
      "value": "#00d9ff"         // Electric cyan (matches Website 2.0 accent color)
    },
    "shape": {
      "type": "circle",          // Simple circular particles ("stars")
      "stroke": {
        "width": 0,
        "color": "#000000"
      }
    },
    "opacity": {
      "value": 0.5,
      "random": false,
      "anim": {
        "enable": false
      }
    },
    "size": {
      "value": 2,                // Small, subtle size
      "random": true,
      "anim": {
        "enable": false
      }
    },
    "line_linked": {
      "enable": true,            // Neural threads enabled
      "distance": 150,
      "color": "#333333",        // Subtle dark gray (contrasts with glowing stars)
      "opacity": 0.4,            // Low opacity (non-distracting)
      "width": 1
    },
    "move": {
      "enable": true,            // Gentle drifting effect
      "speed": 0.5,              // Very slow speed
      "direction": "none",
      "random": false,
      "straight": false,
      "out_mode": "out",
      "bounce": false,
      "attract": {
        "enable": false
      }
    }
  },
  "interactivity": {
    "detect_on": "canvas",       // Interactive laser detection
    "events": {
      "onhover": {
        "enable": true,
        "mode": "grab"           // Cursor connects to nearby particles ("laser" effect)
      },
      "onclick": {
        "enable": true,
        "mode": "push"           // Stars scatter when user clicks
      },
      "resize": true
    },
    "modes": {
      "grab": {
        "distance": 140,
        "line_linked": {
          "opacity": 1           // Stronger connection on hover
        }
      },
      "push": {
        "particles_nb": 4        // Add particles on click
      }
    }
  },
  "retina_detect": true
});

console.log('🔥 Hacker Matrix animation initialized');
console.log('   Particles: 150 (constellation field)');
console.log('   Neural threads: Enabled (dark gray, 0.4 opacity)');
console.log('   Interactive laser: Hover grab + Click push');
