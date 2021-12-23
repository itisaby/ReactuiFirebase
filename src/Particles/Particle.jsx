import ReactParticles from "react-particles-js";

const particlesConfig = {
  particles: {
    number: {
      value: 100,
    },
    size: {
      value: 3,
    },
  },
  interactivity: {
    events: {
      onhover: {
        enable: true,
        mode: "repulse",
      },
    },
  },
};

function Particles({ children }) {
  return (
    <div style={{ position: "relative" 
    }}>
      <ReactParticles
        params={particlesConfig}
        style={{
          position: "absolute",
          zIndex: 0,
          left: 0,
          right: 0,
          bottom: 0,
          top: 0,
        }}
      />
      {children && <div style={{ position: "relative" }}>{children}</div>}
    </div>
  );
}

export default Particles;
