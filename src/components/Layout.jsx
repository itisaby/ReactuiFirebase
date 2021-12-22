import React from "react";
import { Container, Box } from "@chakra-ui/react";
import { Navbar } from "./Navbar";

export function Layout(props) {
  return (
    <>
      <Navbar />
      <Container maxW="container.lg">{props.children}</Container>
    </>
  );
}
