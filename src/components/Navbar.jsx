import {
  Box,
  HStack,
  IconButton,
  Spacer,
  useColorMode,
  useColorModeValue,
} from "@chakra-ui/react";
import React from "react";
import { FaMoon, FaSun } from "react-icons/fa";
import { useAuth } from "../contexts/AuthContext";
import Navlink from "./Navlink";

export function Navbar() {
  const { toggleColorMode } = useColorMode();

  const { currentUser, logout } = useAuth();

  return (
    <Box
      borderBottom="2px"
      borderBottomColor={useColorModeValue("gray.100", "gray.700")}
      mb={4}
    >
      <HStack py={4} justifyContent="flex-end" maxW="container.lg" mx="auto" >

        <Navlink to="/" name="Firebase Authentication" size="lg" mr={5} ml={5} />
        <Spacer />
       
        {!currentUser && <Navlink to="/login" name="Login" />}
        {!currentUser && <Navlink to="/register" name="Register" />}
        {currentUser && <Navlink to="/profile" name="Profile" />}
        {currentUser && <Navlink to="/protected-page" name="Payment" />}
        {currentUser && <Navlink
          to="/logout"
          name="Logout"
          onClick={async (e) => {
            e.preventDefault();
           // handle logout
            logout();
          }}
        />}
        <IconButton
          variant="outline"
          icon={useColorModeValue(<FaSun />, <FaMoon />)}
          onClick={toggleColorMode}
          aria-label="toggle-dark-mode"
        />
      </HStack>
    </Box>
  );
}
