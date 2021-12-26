import {
  Badge,
  chakra,
  Code,
  Heading,
  List,
  ListItem,
  OrderedList,
  Tag,
  Text,
  Image,
} from "@chakra-ui/react";
import React from "react";
import { Layout } from "../components/Layout";
import { Link } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
// import Particles from "react-particles-js";
// import Particles from "../Particles/Particle"
import CallToActionWithAnnotation from "./CalltoAction"

export default function Homepage() {
  const { currentUser } = useAuth();
  return (
    <Layout>
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
        />
          <div
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            width: "100%",
            height: "100%"
          }}
        > */}

      {/* <Heading>Home page</Heading>
      <Text my={6}>{`The current user is ${currentUser}`}</Text> */}
      <CallToActionWithAnnotation />
      {/* <Image
            alignSelf="center"
            // mt={isNotSmallerScreen ? "0" : "12"}
            // mb={isNotSmallerScreen ? "0" : "12"}
            borderRadius="full"
            backgroundColor="transparent"
            boxShadow="lg"
            boxSize="1000px"
            src={currentUser.photoURL}
          /> */}
      
    </Layout>
  );
}
