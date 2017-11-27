import ingressGenerator from './ingressGenerator';

describe('Ingress generator', () => {
  it('should generate a single path if connect port is not supplied', () => {
    const options = {
      name: 'name',
      datalabInfo: {
        name: 'testlab',
        domain: 'test-datalabs.nerc.ac.uk',
      },
      ingressName: 'name-ingress',
      serviceName: 'name-service',
      port: 80,
    };
    const template = ingressGenerator.createIngress(options);

    return expect(template).resolves.toMatchSnapshot();
  });

  it('should generate multiple paths if connect port is supplied', () => {
    const options = {
      name: 'name',
      datalabInfo: {
        name: 'testlab',
        domain: 'test-datalabs.nerc.ac.uk',
      },
      ingressName: 'name-ingress',
      serviceName: 'name-service',
      port: 80,
      connectPort: 8000,
    };
    const template = ingressGenerator.createIngress(options);

    return expect(template).resolves.toMatchSnapshot();
  });
});