import React from "react";
import { Layout } from "../components/Layout";
import {
  Badge,
  chakra,
  Code,
  Container,
  Stack,
  Circle,
  Flex,
  Box,
  Text,
  Button,
  FormControl,
  FormLabel,
  Input,
  InputGroup,
  HStack,
  InputRightElement,
  Heading,
  useColorModeValue,
  Link,
} from "@chakra-ui/react";
import { Image } from "@chakra-ui/image";
import { useMediaQuery } from "@chakra-ui/media-query";
import { Card } from "../components/Card";
import { useAuth } from "../contexts/AuthContext";
import { useColorMode } from "@chakra-ui/color-mode";
import { useState } from 'react';
import { ViewIcon, ViewOffIcon } from '@chakra-ui/icons';

export default function Profilepage() {
  const { colorMode } = useColorMode();
  const isDark = colorMode === "dark";
  const { currentUser } = useAuth();
  const [isNotSmallerScreen] = useMediaQuery("(min-width:600px)");
  const [showPassword, setShowPassword] = useState(false);

  return (
    <Layout>
      {/* <Heading>
        Profile page
        <Badge colorScheme='green' fontSize='lg' mx={4}>
          Protected Page
        </Badge>
      </Heading>
      
      <Container maxW='container.lg' overflowX='auto' py={4}>
        <chakra.pre>
          {JSON.stringify(currentUser, null, 2)}
        </chakra.pre>
      </Container> */}
      <Stack>
        <Circle
          position="absolute"
          bg="blue.100"
          opacity="0.1"
          w="300px"
          h="300px"
          alignSelf="flex-end"
        />
        <Flex
          direction={isNotSmallerScreen ? "row" : "column"}
          spacing="200px"
          p={isNotSmallerScreen ? "32" : "0"}
          alignSelf="flex-start"
        >
          <Box mt={isNotSmallerScreen ? "0" : 16} align="flex-start">
            <Text fontSize="5xl" fontWeight="semibold">
              Hi There!
            </Text>
            <Text
              fontSize="7xl"
              fontWeight="bold"
              bgGradient="linear(to-r, cyan.400, blue.500, purple.600)"
              bgClip="text"
            >
              {currentUser.displayName}
            </Text>
            <Text color={isDark ? "gray.200" : "gray.500"}>
              Welcome OnBoard with AI Writer
            </Text>
          </Box>
          <Image
            alignSelf="center"
            mt={isNotSmallerScreen ? "0" : "12"}
            mb={isNotSmallerScreen ? "0" : "12"}
            borderRadius="full"
            backgroundColor="transparent"
            boxShadow="lg"
            boxSize="300px"
            src={currentUser.photoURL}
          />
          <Text
            fontSize="xl"
            fontWeight="bold"
            bgGradient="linear(to-r, cyan.400, blue.500, purple.600)"
            bgClip="text"
          >
            {currentUser.email}
          </Text>
        </Flex>
        <Flex
          direction={isNotSmallerScreen ? "row" : "column"}
          spacing="100px"
          p={isNotSmallerScreen ? "32" : "0"}
          alignSelf="flex-start"
        >
          <Container maxW="container.lg" overflowX="auto" py={4}>
            <Stack spacing={4}>
             
                <Box>
                  <FormControl id="firstName" isRequired>
                    <FormLabel>Name</FormLabel>
                    <Input type="text" />
                  </FormControl>
                </Box>
                
              <FormControl id="email" isRequired>
                <FormLabel>Email address</FormLabel>
                <Input type="email" />
              </FormControl>
              <FormControl id="password" isRequired>
                <FormLabel>Password</FormLabel>
                <InputGroup>
                  <Input type={showPassword ? "text" : "password"} />
                  <InputRightElement h={"full"}>
                    <Button
                      variant={"ghost"}
                      onClick={() =>
                        setShowPassword((showPassword) => !showPassword)
                      }
                    >
                      {showPassword ? <ViewIcon /> : <ViewOffIcon />}
                    </Button>
                  </InputRightElement>
                </InputGroup>
              </FormControl>
              <Stack spacing={10} pt={2}>
                <Button
                  loadingText="Submitting"
                  size="lg"
                  bg={"blue.400"}
                  color={"white"}
                  _hover={{
                    bg: "blue.500",
                  }}
                >
                  Edit
                </Button>
              </Stack>
              
            </Stack>
          </Container>
        </Flex>
      </Stack>
    </Layout>
  );
}
