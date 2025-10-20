/**
 * PHOENIX PROTOCOL - INTERACTIVE HACKER MATRIX
 * Enhanced with CURSOR-FOLLOWING Gaming Effect
 * Version: 2.0 (October 2025)
 */

particlesJS('particles-js', {
  "particles": {
    "number": {
      "value": 150,
      "density": {
        "enable": true,
        "value_area": 800
      }
    },
    "color": {
      "value": "#00d9ff"
    },
    "shape": {
      "type": "circle",
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
      "value": 2,
      "random": true,
      "anim": {
        "enable": false
      }
    },
    "line_linked": {
      "enable": true,
      "distance": 150,
      "color": "#333333",
      "opacity": 0.4,
      "width": 1
    },
    "move": {
      "enable": true,
      "speed": 1.5,
      "direction": "none",
      "random": false,
      "straight": false,
      "out_mode": "out",
      "bounce": false,
      "attract": {
        "enable": true,
        "rotateX": 600,
        "rotateY": 1200
      }
    }
  },
  "interactivity": {
    "detect_on": "canvas",
    "events": {
      "onhover": {
        "enable": true,
        "mode": ["grab", "bubble"]
      },
      "onclick": {
        "enable": true,
        "mode": "repulse"
      },
      "resize": true
    },
    "modes": {
      "grab": {
        "distance": 200,
        "line_linked": {
          "opacity": 1
        }
      },
      "bubble": {
        "distance": 250,
        "size": 4,
        "duration": 2,
        "opacity": 0.8
      },
      "repulse": {
        "distance": 100,
        "duration": 0.4
      }
    }
  },
  "retina_detect": true
});

console.log('âœ¨ INTERACTIVE MATRIX: Cursor-following enabled');
console.log('   ðŸ’« Particles attracted to cursor');
console.log('   ðŸŽ® Gaming effect: Move cursor to control stars');
console.log('   ðŸŽ¯ Click to scatter particles');
