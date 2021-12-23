import React from "react";
import { Layout } from "../components/Layout";
import {
  Badge,
  chakra,
  Code,
  Container,
  Heading,
  Stack,
  Circle,
  Flex,
  Box,
  Text,
  Button,
} from "@chakra-ui/react";
import { Image } from "@chakra-ui/image";
import { useMediaQuery } from "@chakra-ui/media-query";
import { Card } from "../components/Card";
import { useAuth } from "../contexts/AuthContext";
import { useColorMode } from "@chakra-ui/color-mode";


export default function Profilepage() {
  const { colorMode } = useColorMode();
  const isDark = colorMode === "dark";
  const { currentUser } = useAuth();
  const [isNotSmallerScreen] = useMediaQuery("(min-width:600px)");
  
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
        </Flex>
        <Flex
          direction={isNotSmallerScreen ? "row" : "column"}
          spacing="100px"
          p={isNotSmallerScreen ? "32" : "0"}
          alignSelf="flex-start"
        >
          <Button
            colorScheme="teal"
            size="lg"
            variant="outline"
           
          >
            Button
          </Button>
        </Flex>
      </Stack>
      {/* 
      <Container maxW="container.lg" overflowX="auto" py={4}>
        <chakra.pre>{JSON.stringify(currentUser, null, 2)}</chakra.pre>
      </Container> */}
    </Layout>
  );
}
