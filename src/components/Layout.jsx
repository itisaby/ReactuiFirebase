import React from "react";
import { Container, Box } from "@chakra-ui/react";
import { Navbar } from "./Navbar";


// import Particles from "react-particles-js";
import Particles from "../Particles/Particle";
export function Layout(props) {
  return (
    <>
      <Particles>
        {/* <div> */}
        <Navbar />
        {/* <Nav /> */}
        {/* <Particles
          params={{
            particles: {
              number: {
                value: 200,
                density: {
                  enable: true,
                  value_area: 1000,
                },

              },
            },
          }}
        > */}

        <Container maxW="container.lg">{props.children}</Container>
      </Particles>
      {/* </Particles>
      </div> */}
    </>
  );
}
