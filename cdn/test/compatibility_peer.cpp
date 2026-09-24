#include "pacetun/edge_selection.hpp"
#include <iostream>
#include <stdexcept>

int main() {
  using pacetun::edge_address_index;
  const auto expect=[](std::size_t actual,std::size_t expected){
    if(actual!=expected)throw std::runtime_error("edge selection mismatch");
  };
  expect(edge_address_index(2,0,0,true),0);
  expect(edge_address_index(2,1,0,true),1);
  expect(edge_address_index(2,2,0,true),0);
  expect(edge_address_index(3,1,1,true),2);
  expect(edge_address_index(3,2,1,true),0);
  expect(edge_address_index(3,100,0,false),0);
  expect(edge_address_index(3,100,2,false),2);
  bool threw=false;
  try {edge_address_index(0,0,0,true);} catch(const std::out_of_range&) {threw=true;}
  if(!threw)throw std::runtime_error("empty address list accepted");
  std::cout<<"edge selection tests OK\n";
}
